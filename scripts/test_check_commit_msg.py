"""Тесты проверки формата сообщений коммитов."""

from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from pathlib import Path

import check_commit_msg as ccm


class SubjectTest(unittest.TestCase):
    def test_skips_git_comments_and_blank_lines(self) -> None:
        message = "\n# Please enter the commit message\n\nfix: закрыть тело ответа\n\nтело\n"
        self.assertEqual(ccm.subject_of(message), "fix: закрыть тело ответа")

    def test_empty(self) -> None:
        self.assertEqual(ccm.subject_of("# только комментарий\n\n"), "")


class ProblemsTest(unittest.TestCase):
    def test_valid_subjects(self) -> None:
        for subject in (
            "feat(sensor): минимальный сервис",
            "fix: закрыть тело ответа",
            "ci: проверки безопасности",
            "feat(api)!: несовместимое изменение формата событий",
            "build(deps): bump golang.org/x/net from 0.30.0 to 0.31.0 in /sensor",
            'Revert "feat: что-то сломавшее"',
            "Merge branch 'main' into feature",
        ):
            with self.subTest(subject=subject):
                self.assertEqual(ccm.problems(subject), [])

    def test_invalid_subjects(self) -> None:
        for subject in (
            "Add files via upload",
            "исправил баг",
            "fix:без пробела",
            "fix: ",
            "Fix: тип с заглавной",
            "feature: несуществующий тип",
            "fix(Sensor): область с заглавной",
            "fix(): пустая область",
            "wip",
        ):
            with self.subTest(subject=subject):
                self.assertNotEqual(ccm.problems(subject), [])

    def test_empty_subject(self) -> None:
        self.assertEqual(ccm.problems(""), ["пустое сообщение коммита"])

    def test_length_limit_counts_characters_not_bytes(self) -> None:
        # Кириллица занимает два байта в UTF-8; предел — в символах.
        at_limit = "fix: " + "ж" * (ccm.MAX_SUBJECT - len("fix: "))
        self.assertEqual(ccm.problems(at_limit), [])
        self.assertTrue(ccm.problems(at_limit + "ж"))


class ReportTest(unittest.TestCase):
    def test_untrusted_text_never_starts_a_log_line(self) -> None:
        """Строка коммита не должна стать командой раннера GitHub Actions."""
        out = io.StringIO()
        malicious = "::add-mask::секрет\n::error::поддельная ошибка"
        count = ccm.report([("abc1234", malicious)], out.write)

        self.assertGreater(count, 0)
        for line in out.getvalue().splitlines():
            self.assertFalse(line.lstrip().startswith("::"), line)


class RangeTest(unittest.TestCase):
    def test_rejects_non_sha(self) -> None:
        with self.assertRaises(ValueError):
            ccm.commit_subjects("--all", "b" * 40)

    def test_real_repository(self) -> None:
        """Проверка по настоящему репозиторию git: слияния пропускаются."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args: str) -> str:
                return subprocess.run(  # noqa: S603
                    ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],  # noqa: S607
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            git("init", "-q", "-b", "main")
            git("commit", "-q", "--allow-empty", "-m", "Initial upload")
            base = git("rev-parse", "HEAD")
            git("checkout", "-q", "-b", "feature")
            git("commit", "-q", "--allow-empty", "-m", "feat: хорошее сообщение")
            git("commit", "-q", "--allow-empty", "-m", "плохое сообщение")
            git("checkout", "-q", "main")
            git("commit", "-q", "--allow-empty", "-m", "docs: параллельная правка")
            git("checkout", "-q", "feature")
            git("merge", "-q", "--no-edit", "main")
            head = git("rev-parse", "HEAD")

            subjects = [s for _, s in ccm.commit_subjects(base, head, cwd=tmp)]

        # Коммит слияния не проверяется; коммит из main попадает в диапазон,
        # потому что его влили в ветку.
        self.assertNotIn("Merge branch 'main' into feature", subjects)
        self.assertIn("плохое сообщение", subjects)
        self.assertIn("feat: хорошее сообщение", subjects)
        self.assertNotIn("Initial upload", subjects)


class MainTest(unittest.TestCase):
    def test_file_mode(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("fix: правильное сообщение\n")
        self.assertEqual(ccm.main(["--file", fh.name]), 0)

        Path(fh.name).write_text("неправильное сообщение\n", encoding="utf-8")
        self.assertEqual(ccm.main(["--file", fh.name]), 1)
        Path(fh.name).unlink()


if __name__ == "__main__":
    unittest.main()
