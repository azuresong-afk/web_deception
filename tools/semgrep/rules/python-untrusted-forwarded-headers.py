# Тестовые примеры для правила python-untrusted-forwarded-headers.


def client_ip(request):
    # ruleid: python-untrusted-forwarded-headers
    ip = request.headers.get("x-forwarded-for")

    # ruleid: python-untrusted-forwarded-headers
    ip = request.headers["X-Real-IP"]

    # ok: python-untrusted-forwarded-headers
    agent = request.headers.get("user-agent")

    # ok: python-untrusted-forwarded-headers
    ip = request.client.host

    return ip, agent
