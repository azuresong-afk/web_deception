# Тестовые примеры для правила python-untrusted-forwarded-headers.


def client_ip(request):
    # ruleid: python-untrusted-forwarded-headers
    ip = request.headers.get("x-forwarded-for")

    # ruleid: python-untrusted-forwarded-headers
    ip = request.headers["X-Real-IP"]

    # ruleid: python-untrusted-forwarded-headers
    proto = request.headers.get("X-Forwarded-Proto")

    # ruleid: python-untrusted-forwarded-headers
    ip = request.headers.get("x_forwarded_for")

    # ok: python-untrusted-forwarded-headers
    agent = request.headers.get("user-agent")

    # ok: python-untrusted-forwarded-headers
    ip = request.client.host

    return ip, agent, proto
