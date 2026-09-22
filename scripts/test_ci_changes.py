"""Тесты выбора заданий CI.

Главное, что здесь проверяется: при любой неопределённости запускается всё.
Пропущенная проверка стоит дороже, чем лишняя.
"""

from __future__ import annotations

import subprocess
import unittest

import ci_changes as cc

SHA_A = "a" * 40
SHA_B = "b" * 40
ALL = {"go": True, "python": True, "containers": True}
NONE = {"go": False, "python": False, "containers": False}


def pr_env() -> dict[str, str]:
    return {"GITHUB_EVENT_NAME": "pull_request", "BASE_SHA": SHA_A, "HEAD_SHA": SHA_B}


class ClassifyTest(unittest.TestCase):
    def test_docs_only_runs_nothing(self) -> None:
        self.assertEqual(cc.classify(["docs/guide.md", "README.md", "CLAUDE.md"]), NONE)

    def test_sensor_change_runs_go_and_containers(self) -> None:
        result = cc.classify(["sensor/cmd/sensor/main.go"])
        self.assertEqual(result, {"go": True, "python": False, "containers": True})

    def test_controlplane_change_runs_python_and_containers(self) -> None:
        result = cc.classify(["controlplane/src/webdeception_cp/app.py"])
        self.assertEqual(result, {"go": False, "python": True, "containers": True})

    def test_linter_update_runs_go(self) -> None:
        self.assertTrue(cc.classify(["tools/golangci-lint/go.sum"])["go"])
        self.assertTrue(cc.classify(["tools/actionlint/go.mod"])["go"])

    def test_semgrep_rules_do_not_run_go(self) -> None:
        # Правила Semgrep проверяет задание sast, которое запускается всегда.
        self.assertFalse(cc.classify(["tools/semgrep/README.md"])["go"])

    def test_vulnerability_tool_update_runs_go(self) -> None:
        self.assertTrue(cc.classify(["tools/govulncheck/go.sum"])["go"])

    def test_hook_changes_run_go(self) -> None:
        # Хуки тестируются в задании Go: им нужен Go для gitleaks.
        for path in (".githooks/pre-commit", ".gitleaks.toml", "scripts/check_commit_msg.py"):
            with self.subTest(path=path):
                self.assertTrue(cc.classify([path])["go"])

    def test_scanner_image_update_runs_containers(self) -> None:
        self.assertTrue(cc.classify(["tools/scanners/compose.yaml"])["containers"])

    def test_compose_change_runs_containers_only(self) -> None:
        result = cc.classify(["deploy/compose/compose.yaml"])
        self.assertEqual(result, {"go": False, "python": False, "containers": True})

    def test_makefile_or_workflow_runs_everything(self) -> None:
        for path in ("Makefile", ".github/workflows/ci.yml"):
            with self.subTest(path=path):
                self.assertEqual(cc.classify([path]), ALL)

    def test_similar_prefix_does_not_match(self) -> None:
        # "sensor-docs/" не каталог sensor/, "Makefile.bak" не Makefile.
        # Второй случай поймал этот тест в первой версии скрипта.
        self.assertEqual(cc.classify(["sensor-docs/x.md", "Makefile.bak"]), NONE)

    def test_dockerignore_is_exact_file(self) -> None:
        self.assertTrue(cc.classify([".dockerignore"])["containers"])
        self.assertFalse(cc.classify([".dockerignore.orig"])["containers"])


class DecideTest(unittest.TestCase):
    def test_push_runs_everything(self) -> None:
        decision, _ = cc.decide({"GITHUB_EVENT_NAME": "push"}, diff=lambda b, h: [])
        self.assertEqual(decision, ALL)

    def test_pull_request_uses_diff(self) -> None:
        decision, _ = cc.decide(pr_env(), diff=lambda b, h: ["docs/x.md"])
        self.assertEqual(decision, NONE)

    def test_git_failure_runs_everything(self) -> None:
        def broken(base: str, head: str) -> list[str]:
            raise subprocess.CalledProcessError(128, "git")

        decision, reason = cc.decide(pr_env(), diff=broken)
        self.assertEqual(decision, ALL)
        self.assertIn("проверяется всё", reason)

    def test_invalid_sha_runs_everything(self) -> None:
        env = {**pr_env(), "BASE_SHA": "--output=/tmp/x"}
        decision, _ = cc.decide(env)
        self.assertEqual(decision, ALL)

    def test_missing_sha_runs_everything(self) -> None:
        decision, _ = cc.decide({"GITHUB_EVENT_NAME": "pull_request"})
        self.assertEqual(decision, ALL)


class ChangedFilesTest(unittest.TestCase):
    def test_rejects_option_injection(self) -> None:
        with self.assertRaises(ValueError):
            cc.changed_files("--output=/etc/passwd", SHA_B)

    def test_rejects_short_or_uppercase_sha(self) -> None:
        for bad in ("abc123", "A" * 40, SHA_A + "0"):
            with self.subTest(sha=bad), self.assertRaises(ValueError):
                cc.changed_files(bad, SHA_B)


if __name__ == "__main__":
    unittest.main()
