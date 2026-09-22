"""HTTP-приложение control plane.

На этом шаге здесь только проверки живости и готовности — те же, что
у сенсора, и с той же семантикой. Приём событий, корреляция и API
для дашборда появятся на этапах 3-5.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from webdeception_cp.config import Config


def create_app(config: Config) -> FastAPI:
    """Собирает приложение под переданную конфигурацию."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Готовность выставляется после запуска и снимается до остановки.
        # Сейчас между этими точками ничего нет, но на этапе 3 здесь появятся
        # подключение к базе и подписка на очередь — и тогда важно, чтобы
        # готовность наступала только после них.
        app.state.ready = True
        try:
            yield
        finally:
            app.state.ready = False

    app = FastAPI(
        title="web-deception control plane",
        # Это версия контракта API, а не версия сборки продукта. FastAPI
        # требует её непустой, когда включена документация. Версия сборки
        # сюда не попадает намеренно: она нужна только в логах (угроза T5).
        version="1",
        # Интерактивная документация FastAPI по умолчанию открыта на /docs,
        # /redoc и /openapi.json. Это публикует полный список эндпоинтов,
        # их параметры и структуры данных — готовую карту для атакующего.
        # Удобство разработки не должно включаться само по себе, поэтому
        # по умолчанию всё три выключены и включаются только явным флагом.
        docs_url="/docs" if config.enable_docs else None,
        redoc_url="/redoc" if config.enable_docs else None,
        openapi_url="/openapi.json" if config.enable_docs else None,
        lifespan=lifespan,
    )

    # До выполнения lifespan сервис не готов. Важно задать значение здесь:
    # без него первый же запрос к /readyz упал бы с AttributeError,
    # то есть проверка готовности сама стала бы источником ошибки.
    app.state.ready = False

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Заголовки безопасности на каждом ответе.

        Ставятся здесь, а не в каждом обработчике: защита, которую нужно
        не забыть добавить, рано или поздно будет забыта.
        """
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz() -> str:
        """Живость: процесс запущен и отвечает. Всегда 200, пока жив."""
        return "ok\n"

    @app.get("/readyz", response_class=PlainTextResponse)
    async def readyz() -> Response:
        """Готовность: можно ли слать сюда запросы.

        Отличие от живости принципиальное. Провал живости в оркестраторе
        означает «убить и перезапустить», провал готовности — «увести
        трафик, процесс не трогать». Если бы обе проверки отвечали
        одинаково, недоступность базы данных превращалась бы в бесконечную
        петлю перезапусков.
        """
        if not app.state.ready:
            return PlainTextResponse("not ready\n", status_code=503)
        return PlainTextResponse("ready\n")

    app.add_exception_handler(StarletteHTTPException, _http_error_handler)

    return app


async def _http_error_handler(request: Request, exc: Exception) -> Response:
    """Единый минимальный формат ошибок.

    FastAPI по умолчанию отвечает JSON вида {"detail": "Not Found"}. Две
    причины заменить его:

    1. Поле detail в некоторых случаях содержит данные из запроса, то есть
       текст, выбранный атакующим. Мы его не отражаем вообще — вместо этого
       отдаём стандартное название кода состояния.
    2. Форма ответа выдаёт фреймворк. Сегодня control plane не доступен
       атакующему, но на этапах 5-6 у него появятся дашборд и webhook,
       и единый безликий формат ошибок будет уже не запасом, а требованием.
    """
    status = exc.status_code if isinstance(exc, StarletteHTTPException) else 500
    headers = exc.headers if isinstance(exc, StarletteHTTPException) else None

    # Название берём из стандартной таблицы HTTP, а не из текста исключения:
    # так в ответ физически не может попасть ничего из запроса.
    phrase = HTTPStatus(status).phrase.lower()

    return PlainTextResponse(f"{phrase}\n", status_code=status, headers=headers)
