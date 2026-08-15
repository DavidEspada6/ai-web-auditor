import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_web_auditor.cli import main
from ai_web_auditor.projects import create_project, list_projects, load_project, load_project_config, slug_project_name


class ProjectTests(unittest.TestCase):
    def test_create_load_and_list_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            projects_dir = Path(tmpdir)
            project = create_project(
                "Cliente Demo",
                target="https://example.com/app",
                client="Cliente Demo SL",
                auditor="David",
                engagement="Practica 1",
                projects_dir=projects_dir,
            )
            loaded = load_project("cliente-demo", projects_dir=projects_dir)
            config = load_project_config(loaded)
            projects = list_projects(projects_dir)

        self.assertEqual(project.id, "cliente-demo")
        self.assertEqual(loaded.client, "Cliente Demo SL")
        self.assertEqual(config.target.url, "https://example.com/app")
        self.assertEqual(config.scope.allowed_hosts, ["example.com"])
        self.assertEqual(len(projects), 1)
        self.assertEqual(projects[0].id, "cliente-demo")

    def test_slug_project_name(self):
        self.assertEqual(slug_project_name("Cliente Demo / Produccion"), "cliente-demo-produccion")

    def test_cli_project_init_outputs_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            projects_dir = Path(tmpdir)
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    [
                        "project",
                        "init",
                        "Cliente Demo",
                        "--target",
                        "https://example.com",
                        "--client",
                        "Cliente Demo SL",
                        "--projects-dir",
                        str(projects_dir),
                        "--json",
                    ]
                )
            data = json.loads(output.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(data["id"], "cliente-demo")
        self.assertEqual(data["target_url"], "https://example.com/")


if __name__ == "__main__":
    unittest.main()
