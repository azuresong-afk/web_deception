# Тестовые примеры для правила python-mac-compare-constant-time.
import hashlib
import hmac


def verify(
    key: bytes, message: bytes, received: str, expected_mac: str, signature: str, token: str
) -> bool:
    # ruleid: python-mac-compare-constant-time
    if received == signature:
        return True

    # ruleid: python-mac-compare-constant-time
    if hmac.new(key, message, hashlib.sha256).hexdigest() == received:
        return True

    # ruleid: python-mac-compare-constant-time
    if received == expected_mac:
        return True

    # ruleid: python-mac-compare-constant-time
    if received != expected_mac:
        return False

    # ok: python-mac-compare-constant-time
    if hmac.compare_digest(received, expected_mac):
        return True

    # ok: python-mac-compare-constant-time
    if len(expected_mac) != 64:
        return False

    # ok: python-mac-compare-constant-time
    return received == token
