const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const fs = require("node:fs/promises");
const path = require("node:path");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");

async function main() {
  const fixture = spawn(process.env.PYTHON || "python", [path.join(__dirname, "serve_browser_fixture.py")], { windowsHide: true });
  const exited = once(fixture, "close");
  fixture.stderr.pipe(process.stderr);
  let browser;
  const screenshots = path.resolve("outputs/ui-v0.26.0");
  try {
    const ready = await new Promise((resolve, reject) => {
      let data = "";
      const timer = setTimeout(() => reject(new Error("Fixture startup timed out")), 15000);
      fixture.on("error", reject);
      fixture.stdout.on("data", chunk => {
        data += chunk.toString();
        if (data.includes("\n")) {
          clearTimeout(timer);
          resolve(JSON.parse(data.split("\n")[0]));
        }
      });
      fixture.on("exit", code => { clearTimeout(timer); reject(new Error(`Fixture exited: ${code}`)); });
    });
    browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, locale: "es-ES" });
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/*", route => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
    await page.goto(ready.url);
    await page.waitForFunction(() => !document.querySelector("#audit-preset").disabled);
    await page.click("#use-lab");
    assert.equal(await page.locator("#port-timeout").inputValue(), "0.5");
    assert.equal(await page.locator("#port-timeout").evaluate(input => input.validity.valid), true);
    await page.locator("#auth-profile").selectOption("member");
    const original = await page.locator("#auth-extra-headers").inputValue();
    for (const preset of ["quick", "extended", "standard"]) {
      await page.selectOption("#audit-preset", preset);
      assert.match(await page.locator("#target").inputValue(), /^http:\/\/127\.0\.0\.1:/);
      assert.equal(await page.locator("#allow-private").isChecked(), true);
      assert.equal(await page.locator("#auth-extra-headers").inputValue(), original);
      assert.equal(await page.locator('[data-module="ports"]').isChecked(), false);
      assert.equal(await page.locator('[data-module="subdomains"]').isChecked(), false);
      assert.equal(await page.locator("#scan-form").evaluate(form => form.checkValidity()), true);
    }
    await page.waitForFunction(() => document.querySelector("#configuration-status").dataset.state === "valid");
    await page.locator("#allowed-hosts").fill("outside.test");
    await page.waitForFunction(() => document.querySelector("#configuration-status").dataset.state === "error");
    await page.locator("#allowed-hosts").fill("127.0.0.1");
    await page.locator("#auth-profile").selectOption("public");
    await page.locator("#delay").fill("0");
    assert.equal(await page.locator("#audit-preset").inputValue(), "");
    await page.waitForFunction(() => document.querySelector("#configuration-status").dataset.state === "valid");
    await fs.mkdir(screenshots, { recursive: true });
    await page.screenshot({ path: path.join(screenshots, "configuration-desktop.png") });

    const scanPromise = page.waitForResponse(response => response.url().endsWith("/api/scan"));
    await page.click("#run-scan");
    const scan = await (await scanPromise).json();
    assert.equal(scan.ok, true, scan.error);
    assert.equal(scan.result.status, "completed");
    assert.ok(scan.result.findings.some(item => item.id === "AUTH-BASIC-OVER-HTTP"));
    assert.equal(scan.result.execution.crawler.max_pages, 25);
    await page.waitForFunction(() => !document.querySelector("#run-scan").disabled);

    for (const tab of await page.locator(".tab").all()) {
      await tab.click();
      assert.equal(Math.round((await tab.boundingBox()).height), 38);
      const overflow = await page.evaluate(() => ({
        page: document.documentElement.scrollWidth, viewport: window.innerWidth,
        elements: [...document.querySelectorAll("body *")].filter(item => item.getBoundingClientRect().right > window.innerWidth + 1)
          .slice(0, 12).map(item => `${item.tagName}.${item.className}#${item.id}`),
      }));
      if (overflow.page > overflow.viewport) {
        await page.screenshot({ path: path.join(screenshots, "overflow.png") });
        throw new Error(`Overflow in ${await tab.textContent()}: ${JSON.stringify(overflow)}`);
      }
    }
    await page.click('[data-tab="inventory"]');
    const header = page.locator('table[data-table="inventory"] th').first();
    const before = await header.boundingBox();
    const handle = await header.locator(".column-resizer").boundingBox();
    await page.mouse.move(handle.x + handle.width / 2, handle.y + handle.height / 2);
    await page.mouse.down();
    await page.mouse.move(handle.x + 90, handle.y + handle.height / 2);
    await page.mouse.up();
    assert.ok((await header.boundingBox()).width > before.width + 30);
    await page.click('[data-tab="report"]');
    const reportPromise = page.waitForResponse(response => response.url().endsWith("/api/report"));
    await page.click("#generate-report");
    const report = await (await reportPromise).json();
    assert.equal(report.ok, true, report.error);
    await page.waitForFunction(() => !document.querySelector("#download-pdf").disabled);
    const downloadPromise = page.waitForEvent("download");
    await page.click("#download-pdf");
    const download = await downloadPromise;
    const pdf = await fs.readFile(await download.path());
    assert.equal(pdf.subarray(0, 4).toString(), "%PDF");

    await page.selectOption("#auth-profile", "member");
    const [secondResponse] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith("/api/scan")),
      page.click("#run-scan"),
    ]);
    const second = await secondResponse.json();
    assert.equal(second.ok, true, second.error);
    await page.waitForFunction(() => !document.querySelector("#run-compare").disabled);
    await page.click('[data-tab="compare"]');
    await page.selectOption("#compare-baseline", scan.history_entry.id);
    await page.selectOption("#compare-current", second.history_entry.id);
    const [compareResponse] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith("/api/compare")),
      page.click("#run-compare"),
    ]);
    assert.equal((await compareResponse.json()).ok, true);
    await page.locator("#compare-output .metric").first().waitFor();
    await page.click('[data-tab="history"]');
    await page.click("#refresh-history");
    await page.locator("[data-load-history]").first().waitFor();
    await page.locator("[data-load-history]").first().click();
    await page.waitForFunction(() => document.querySelector('[data-tab="summary"]').classList.contains("active"));
    assert.equal(await page.locator("#compare-output").textContent(), "");
    await page.click('[data-tab="dashboard"]');
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: path.join(screenshots, "dashboard-desktop.png") });
    for (const width of [1024, 390]) {
      await page.setViewportSize({ width, height: 900 });
      for (const tab of await page.locator(".tab").all()) {
        await tab.click();
        const metrics = await page.evaluate(() => ({ page: document.documentElement.scrollWidth, viewport: window.innerWidth }));
        assert.ok(metrics.page <= metrics.viewport, `Overflow at ${width}px in ${await tab.textContent()}: ${JSON.stringify(metrics)}`);
      }
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator("#configuration-status").scrollIntoViewIfNeeded();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.screenshot({ path: path.join(screenshots, "configuration-mobile.png") });
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ ok: true, presets: 3, tabs: await page.locator(".tab").count(), widths: [1440, 1024, 390], screenshots }, null, 2));
  } finally {
    if (browser) await browser.close();
    fixture.stdin.end("stop\n");
    await exited;
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
