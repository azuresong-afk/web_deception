# Тестовые примеры для правила python-no-sensitive-http-logging.
import logging

logger = logging.getLogger(__name__)


async def handler(request):
    # ruleid: python-no-sensitive-http-logging
    logger.info("запрос: %s", request.headers)

    # ruleid: python-no-sensitive-http-logging
    logger.warning("вход", extra={"fields": {"auth": request.headers.get("authorization")}})

    # ruleid: python-no-sensitive-http-logging
    logger.info(f"cookie: {request.headers['Cookie']}")

    # ruleid: python-no-sensitive-http-logging
    logger.debug("тело: %s", await request.body())

    # ruleid: python-no-sensitive-http-logging
    logger.info("параметры: %s", request.query_params)

    # ruleid: python-no-sensitive-http-logging
    logger.info("адрес: %s", request.url)

    # ruleid: python-no-sensitive-http-logging
    logging.error("cookies: %s", request.cookies)

    # Путь через переменную тоже ловится.
    headers = dict(request.headers)
    # ruleid: python-no-sensitive-http-logging
    logger.error("сбой", extra={"fields": {"h": headers}})

    # ok: python-no-sensitive-http-logging
    logger.info("запрос", extra={"fields": {"method": request.method, "path": request.url.path}})

    # ok: python-no-sensitive-http-logging
    logger.info("клиент: %s", request.headers.get("user-agent"))
