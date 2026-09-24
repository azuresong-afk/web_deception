"""Тесты проверки политики контейнеров.

Каждое правило обязано хотя бы раз упасть на плохом примере. Проверка,
которую никто не видел красной, ничего не доказывает: она может не работать
вовсе и всё равно показывать «соблюдено».

Запуск: python -m unittest discover -s scripts
"""

from __future__ import annotations

import shutil
import unittest

import check_containers as cc

DIGEST = "@sha256:" + "a" * 64

GOOD_SERVICE: dict[str, object] = {
    "image": "postgres:18-alpine" + DIGEST,
    "user": "70:70",
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "ports": [{"host_ip": "127.0.0.1", "published": "5432", "target": 5432}],
    "mem_limit": 1024,
    "pids_limit": 64,
}

GOOD_DOCKERFILE = f"""
FROM golang:1.27{DIGEST} AS build
RUN go build -o /out/app .

FROM gcr.io/distroless/static{DIGEST}
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
"""


def rules_for_service(**overrides: object) -> set[str]:
    service = {**GOOD_SERVICE, **overrides}
    return {v.rule for v in cc.check_compose({"services": {"svc": service}})}


def rules_for_dockerfile(text: str) -> set[str]:
    return {v.rule for v in cc.check_dockerfile("Dockerfile", text)}


class ComposeRulesTest(unittest.TestCase):
    def test_compliant_service_passes(self) -> None:
        self.assertEqual(rules_for_service(), set())

    def test_c1_unpinned_image(self) -> None:
        self.assertIn("C1", rules_for_service(image="postgres:18-alpine"))

    def test_c1_locally_built_image_is_checked_via_dockerfile(self) -> None:
        self.assertNotIn("C1", rules_for_service(image="webdeception/sensor:dev", build={}))

    def test_c2_latest_tag(self) -> None:
        self.assertIn("C2", rules_for_service(image="postgres:latest"))

    def test_c2_registry_port_is_not_a_tag(self) -> None:
        # Двоеточие в адресе реестра — это порт, а не тег.
        self.assertNotIn("C2", rules_for_service(image="registry:5000/postgres" + DIGEST))

    def test_c3_missing_or_root_user(self) -> None:
        for user in ("", "0", "0:0", "root", "root:root"):
            with self.subTest(user=user):
                self.assertIn("C3", rules_for_service(user=user))

    def test_c4_capabilities_not_dropped(self) -> None:
        self.assertIn("C4", rules_for_service(cap_drop=["NET_RAW"]))
        self.assertIn("C4", rules_for_service(cap_drop=None))

    def test_c5_privilege_escalation_allowed(self) -> None:
        self.assertIn("C5", rules_for_service(security_opt=[]))

    def test_c5_accepts_equals_form(self) -> None:
        self.assertNotIn("C5", rules_for_service(security_opt=["no-new-privileges=true"]))

    def test_c6_port_on_all_interfaces(self) -> None:
        for host_ip in ("", "0.0.0.0", "10.0.0.5"):  # noqa: S104
            with self.subTest(host_ip=host_ip):
                ports = [{"host_ip": host_ip, "published": "80", "target": 80}]
                self.assertIn("C6", rules_for_service(ports=ports))

    def test_c7_missing_limits(self) -> None:
        self.assertIn("C7", rules_for_service(mem_limit=None))
        self.assertIn("C7", rules_for_service(pids_limit=None))


class BuildContextRulesTest(unittest.TestCase):
    SHA = "4bb7cd5f46921959f034455e5615782481966177"

    def rules_for_build(self, build: dict[str, object]) -> set[str]:
        return rules_for_service(image="webdeception/demo:dev", build=build)

    def test_c8_local_context_is_fine(self) -> None:
        self.assertNotIn("C8", self.rules_for_build({"context": "/src/deploy/demo/x"}))

    def test_c8_git_context_pinned_by_sha(self) -> None:
        pinned = f"https://github.com/owner/repo.git#{self.SHA}"
        self.assertNotIn("C8", self.rules_for_build({"context": pinned}))
        self.assertNotIn(
            "C8", self.rules_for_build({"context": ".", "additional_contexts": {"src": pinned}})
        )
        # Подкаталог после SHA допустим.
        self.assertNotIn("C8", self.rules_for_build({"context": pinned + ":sub/dir"}))

    def test_c8_git_context_by_branch_or_tag(self) -> None:
        for ref in ("", "#main", "#v1.2.3", "#4bb7cd5"):
            with self.subTest(ref=ref):
                url = "https://github.com/owner/repo.git" + ref
                self.assertIn("C8", self.rules_for_build({"context": url}))
                self.assertIn(
                    "C8",
                    self.rules_for_build({"context": ".", "additional_contexts": {"src": url}}),
                )

    def test_c8_ssh_git_context(self) -> None:
        self.assertIn("C8", self.rules_for_build({"context": "git@github.com:owner/repo.git#main"}))


class DockerfileRulesTest(unittest.TestCase):
    def test_compliant_dockerfile_passes(self) -> None:
        self.assertEqual(rules_for_dockerfile(GOOD_DOCKERFILE), set())

    def test_d1_unpinned_base_image(self) -> None:
        text = GOOD_DOCKERFILE.replace(f"golang:1.27{DIGEST}", "golang:1.27")
        self.assertIn("D1", rules_for_dockerfile(text))

    def test_d1_platform_flag_is_handled(self) -> None:
        text = GOOD_DOCKERFILE.replace("FROM golang", "FROM --platform=$BUILDPLATFORM golang")
        self.assertEqual(rules_for_dockerfile(text), set())

    def test_d2_latest(self) -> None:
        text = GOOD_DOCKERFILE.replace(f"golang:1.27{DIGEST}", "golang:latest")
        self.assertIn("D2", rules_for_dockerfile(text))

    def test_d3_no_user_in_final_stage(self) -> None:
        text = GOOD_DOCKERFILE.replace("USER 65532:65532\n", "")
        self.assertIn("D3", rules_for_dockerfile(text))

    def test_d3_user_only_in_build_stage_does_not_count(self) -> None:
        # USER действует только внутри своей стадии: переключение в стадии
        # сборки не делает финальный образ непривилегированным.
        text = GOOD_DOCKERFILE.replace("USER 65532:65532\n", "").replace(
            "RUN go build", "USER 1000\nRUN go build"
        )
        self.assertIn("D3", rules_for_dockerfile(text))

    def test_d3_root_or_named_user(self) -> None:
        for user in ("root", "0", "0:0", "nonroot"):
            with self.subTest(user=user):
                text = GOOD_DOCKERFILE.replace("USER 65532:65532", f"USER {user}")
                self.assertIn("D3", rules_for_dockerfile(text))

    def test_d4_unpinned_syntax_directive(self) -> None:
        unpinned = "# syntax=docker/dockerfile:1\n"
        self.assertIn("D4", rules_for_dockerfile(unpinned + GOOD_DOCKERFILE))
        pinned = f"# syntax=docker/dockerfile:1{DIGEST}\n"
        self.assertNotIn("D4", rules_for_dockerfile(pinned + GOOD_DOCKERFILE))

    def test_d5_add_from_url(self) -> None:
        text = GOOD_DOCKERFILE.replace(
            "COPY --from", "ADD https://example.com/tool.tar.gz /tmp/\nCOPY --from"
        )
        self.assertIn("D5", rules_for_dockerfile(text))

    def test_d6_final_stage_not_distroless(self) -> None:
        text = GOOD_DOCKERFILE.replace(
            f"FROM gcr.io/distroless/static{DIGEST}", f"FROM python:3.13-slim{DIGEST}"
        )
        self.assertEqual(rules_for_dockerfile(text), {"D6"})

    def test_d6_distroless_only_in_build_stage_does_not_count(self) -> None:
        # Distroless в сборочной стадии не делает финальный образ distroless.
        text = f"""
FROM gcr.io/distroless/static{DIGEST} AS certs

FROM debian:13-slim{DIGEST}
COPY --from=certs /etc/ssl /etc/ssl
USER 65532:65532
"""
        self.assertEqual(rules_for_dockerfile(text), {"D6"})

    def test_d6_final_stage_from_named_stage_is_resolved(self) -> None:
        # FROM <стадия> — смотрим на образ, с которого началась та стадия.
        good = f"""
FROM gcr.io/distroless/python3-debian13{DIGEST} AS base

FROM base
USER 65532:65532
"""
        self.assertEqual(rules_for_dockerfile(good), set())
        bad = good.replace("gcr.io/distroless/python3-debian13", "python:3.13-slim")
        self.assertEqual(rules_for_dockerfile(bad), {"D6"})

    def test_d6_distroless_debug_variant(self) -> None:
        # В отладочных вариантах distroless есть busybox с shell.
        for tag in ("debug", "debug-nonroot"):
            with self.subTest(tag=tag):
                text = GOOD_DOCKERFILE.replace(
                    f"gcr.io/distroless/static{DIGEST}", f"gcr.io/distroless/static:{tag}{DIGEST}"
                )
                self.assertEqual(rules_for_dockerfile(text), {"D6"})
        nonroot = GOOD_DOCKERFILE.replace(
            f"gcr.io/distroless/static{DIGEST}", f"gcr.io/distroless/static:nonroot{DIGEST}"
        )
        self.assertEqual(rules_for_dockerfile(nonroot), set())

    def test_d6_not_applied_to_demo_targets(self) -> None:
        # Учебной цели shell разрешён, остальные правила действуют.
        text = GOOD_DOCKERFILE.replace(
            f"FROM gcr.io/distroless/static{DIGEST}", f"FROM python:3.12-slim{DIGEST}"
        )
        self.assertEqual(cc.check_dockerfile("demo", text, product=False), [])
        root = text.replace("USER 65532:65532\n", "")
        rules = {v.rule for v in cc.check_dockerfile("demo", root, product=False)}
        self.assertEqual(rules, {"D3"})

    def test_line_continuations_are_joined(self) -> None:
        text = GOOD_DOCKERFILE.replace(
            f"FROM gcr.io/distroless/static{DIGEST}",
            "FROM \\\n    gcr.io/distroless/static:nonroot",
        )
        self.assertIn("D1", rules_for_dockerfile(text))


class RepositoryFilesTest(unittest.TestCase):
    """Настоящие файлы репозитория соответствуют политике."""

    def test_dockerfiles(self) -> None:
        paths = sorted(cc.DOCKERFILES_DIR.glob("*.Dockerfile"))
        self.assertGreater(len(paths), 0)
        for path in paths:
            with self.subTest(dockerfile=path.name):
                self.assertEqual(cc.check_dockerfile(path.name, path.read_text("utf-8")), [])

    @unittest.skipUnless(shutil.which("docker"), "нужен docker CLI")
    def test_compose(self) -> None:
        for compose_file in cc.COMPOSE_FILES:
            with self.subTest(compose=compose_file.name):
                model = cc.load_compose_model(compose_file)
                self.assertEqual(cc.check_compose(model), [])


if __name__ == "__main__":
    unittest.main()
