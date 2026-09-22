"""Интеграционный тест git-хуков из .githooks.

Запуск: make test-hooks. Нужны git, Go (для gitleaks) и python3.

Хуки проверяются так, как они работают у разработчика: во временном
репозитории включаются хуки проекта и делаются настоящие коммиты — хорошие
и плохие. Проверяется не только код возврата, но и то, что плохой коммит
действительно не создан.

Имя файла намеренно не начинается с test_: обычный `make test-scripts`
запускается там, где Go нет, а этот тест без Go не имеет смысла.
"""

from __future__ import annotations

import os
import secrets
import shutil
import string
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Файлы проекта, от которых зависят хуки.
NEEDED = (
    ".githooks/pre-commit",
    ".githooks/commit-msg",
    ".gitleaks.toml",
    "scripts/check_commit_msg.py",
    "tools/gitleaks/go.mod",
    "tools/gitleaks/go.sum",
)


def fake_github_token() -> str:
    """Токен в формате GitHub, собранный во время теста.

    Не константа в коде: иначе gitleaks нашёл бы «секрет» в истории
    нашего собственного репозитория.
    """
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


@unittest.skipUnless(shutil.which("go") and shutil.which("git"), "нужны go и git")
class HooksTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)

        for name in NEEDED:
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)

        # Изоляция от глобальной настройки git разработчика: подпись коммитов,
        # свои хуки или шаблоны не должны влиять на результат теста.
        empty = self.repo / ".empty-gitconfig"
        empty.write_text("", encoding="utf-8")
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1"}

        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "core.hooksPath", ".githooks")
        # Служебные файлы теста попадают в первый коммит без хуков.
        self.git("add", "-A")
        self.git("commit", "-q", "--no-verify", "-m", "chore: файлы для теста хуков")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 — аргументы задаёт сам тест
            ["git", *args],  # noqa: S607
            cwd=self.repo,
            env=self.env,
            check=check,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def commit(self, message: str) -> subprocess.CompletedProcess[str]:
        return self.git("commit", "-q", "-m", message, check=False)

    def head_count(self) -> int:
        return int(self.git("rev-list", "--count", "HEAD").stdout.strip())

    def write(self, name: str, content: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    # --- сообщения ----------------------------------------------------------

    def test_good_commit_passes(self) -> None:
        self.write("docs/note.md", "заметка\n")
        self.git("add", "docs/note.md")

        result = self.commit("docs: заметка")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.head_count(), 2)

    def test_bad_message_is_rejected(self) -> None:
        self.write("docs/note.md", "заметка\n")
        self.git("add", "docs/note.md")

        result = self.commit("поправил заметку")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("тип(область): описание", result.stderr)
        self.assertEqual(self.head_count(), 1, "коммит не должен был создаться")

    # --- секреты ------------------------------------------------------------

    def test_secret_is_blocked(self) -> None:
        self.write("config.py", f'TOKEN = "{fake_github_token()}"\n')
        self.git("add", "config.py")

        result = self.commit("feat: настройки")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("найден секрет", result.stderr)
        self.assertEqual(self.head_count(), 1, "коммит с секретом не должен был создаться")

    def test_secret_value_is_not_printed(self) -> None:
        token = fake_github_token()
        self.write("config.py", f'TOKEN = "{token}"\n')
        self.git("add", "config.py")

        result = self.commit("feat: настройки")

        self.assertNotIn(token, result.stdout + result.stderr)

    def test_unstaged_secret_does_not_block_other_changes(self) -> None:
        # Проверяется то, что уходит в коммит, а не весь рабочий каталог.
        self.write("scratch.txt", f"{fake_github_token()}\n")
        self.write("docs/note.md", "заметка\n")
        self.git("add", "docs/note.md")

        result = self.commit("docs: заметка")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_secret_file_is_blocked(self) -> None:
        # Случайный пароль без узнаваемого формата — ловится по пути.
        self.write("deploy/compose/secrets/postgres_password", "k3J9x-qq\n")
        self.git("add", "-f", "deploy/compose/secrets/postgres_password")

        result = self.commit("chore: пароль")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.head_count(), 1)

    # --- форматирование -----------------------------------------------------

    def test_unformatted_go_is_rejected(self) -> None:
        self.write("main.go", "package main\nvar   x=1\n")
        self.git("add", "main.go")

        result = self.commit("feat: код")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("main.go", result.stderr)

    def test_checks_index_not_working_tree(self) -> None:
        # В индекс добавлена неотформатированная версия, а файл на диске
        # исправлен после git add. В коммит уйдёт индекс — значит, отказ.
        self.write("main.go", "package main\nvar   x=1\n")
        self.git("add", "main.go")
        self.write("main.go", "package main\n\nvar x = 1\n")

        result = self.commit("feat: код")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("main.go", result.stderr)

    def test_formatted_go_passes(self) -> None:
        self.write("main.go", "package main\n\nvar x = 1\n")
        self.git("add", "main.go")

        result = self.commit("feat: код")

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
