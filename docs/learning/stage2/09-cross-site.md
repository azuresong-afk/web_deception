# Этап 2, шаг 9. Ловушки, которые нельзя вызвать с чужого сайта

> Снимок на момент шага: 2026-09-24. Решение — в
> [ADR-0026](../../adr/0026-cross-site-traps.md). Текущее состояние —
> в [guide.md](../../guide.md), раздел «Сенсор».

## Что и зачем

Ловушка ценна, только если её касание — сигнал об атаке. Но браузер
выполняет запросы, которые ему велит любая открытая страница. Атакующий
кладёт на свой сайт `<img src="https://shop.example/.env">`, и каждый
посетитель его сайта «касается» ловушки со своего адреса и со своими
cookie. На этапе 4 по касаниям появится реакция, и такая страница станет
способом заблокировать чужой адрес или заморозить чужой аккаунт. Это
угроза T2 — межсайтовое срабатывание.

После шага 9 у сенсора есть ловушки, которые чужая страница вызвать
не может:

- ловушка на пути с условием `preflight_only`: срабатывает только на запрос,
  который браузер с чужого сайта не отправит без согласования;
- cookie-ловушка: браузер не отправит её с чужого сайта вовсе.

Ловушки высокой уверенности без такой защиты сенсор больше не принимает.
Для остальных касаний в событии теперь видно, откуда пришёл запрос
(`sec_fetch`). Попутно закрыт долг шага 5: `X-Original-URL` от клиента
больше не доходит до приложения.

## Понятия

- **Простой запрос (CORS)** — `GET`, `HEAD` или `POST` с телом, которое
  умеет отправить HTML-форма. Такой запрос браузер отправит с чужого сайта
  сразу, с cookie пользователя. См. [глоссарий](../../glossary.md).
- **CORS preflight** — для любого другого запроса браузер сначала спрашивает
  сервер `OPTIONS`-запросом, можно ли. Нет разрешения — запроса нет.
- **SameSite=Strict** — cookie с этим атрибутом браузер не отправляет ни с
  каким запросом, пришедшим с чужого сайта.
- **HttpOnly** — cookie не видна скриптам страницы, и они не могут её
  перезаписать.
- **Fetch Metadata (`Sec-Fetch-*`)** — заголовки, которые браузер ставит
  сам: откуда запрос, в каком режиме, для чего. Скрипт страницы их изменить
  не может.
- **Сайт и источник.** Источник (origin) — схема, хост и порт. Сайт — схема
  и регистрируемый домен: `a.shop.example` и `shop.example` — один сайт,
  разные источники. Для `127.0.0.1:8080` и `127.0.0.1:9999` сайт один — порт
  не учитывается. Поэтому в проверке руками чужая страница открыта
  на `localhost`, а не на другом порту `127.0.0.1`.
- **Прореживание событий** — из множества одинаковых событий записывается
  первое за окно времени, остальные только считаются.

## Как это работает

```
запрос ─▶ (защита: CONNECT, заголовки о клиенте, X-Original-URL) ─▶ Guard ─▶ Detector.Inspect
                                                                               │
  1. cookie-ловушки: у запроса cookie с другим значением? ─▶ касание (одно на клиента в минуту)
  2. ловушка на пути:
       preflight к ловушке preflight_only в enforce? ─▶ 204 без CORS, запрос дальше не идёт
       условия выполнены (методы, preflight_only)?   ─▶ касание; enforce — ответ ловушки
  3. переход по странице, а cookie-наживки нет?      ─▶ Set-Cookie к ответу приложения
                                                                               │
                                                                     ReverseProxy ─▶ приложение
```

Что происходит в браузере пользователя, открывшего страницу атакующего:

| Что делает чужая страница | Что видит сенсор | Касание |
|---|---|---|
| `<img src="/.env">` | `GET /.env`, `sec_fetch.site: cross-site` | да, `low`, и видно, что межсайтовое |
| форма `POST` на ловушку с `preflight_only` | простой `POST` | нет: условие не выполнено |
| `fetch` с JSON на ту же ловушку | `OPTIONS` (preflight) | нет; сенсор отвечает без разрешения, браузер сам запрос не отправит |
| любой запрос с cookie-ловушкой | запрос без неё: `SameSite=Strict` | нет |

## Разбор кода

### Условия ловушки: `Trap.Accepts` в `policy/policy.go`

```go
func (t *Trap) Accepts(r *http.Request) bool {
	if t.Methods != nil && !slices.Contains(t.Methods, r.Method) {
		return false
	}
	return !t.PreflightOnly || Preflighted(r)
}
```

- `t.Methods != nil` — поле в политике есть. Пустой список `[]` проверка
  политики отвергает: непонятно, «никакой метод» это или «любой».
- `slices.Contains(t.Methods, r.Method)` — метод прислал атакующий,
  он только сравнивается со списком из политики. Сравнение точное:
  `post` — не `POST`.
- `!t.PreflightOnly || Preflighted(r)` — без условия ловушка принимает
  любой запрос, с условием — только «непростой».

### Какой запрос «непростой»: `Preflighted` в `policy/preflight.go`

```go
switch r.Method {
case http.MethodGet, http.MethodHead, http.MethodPost:
	// «Простые» методы: решает Content-Type.
case http.MethodOptions:
	return false
default:
	return true
}
```

- `GET`, `HEAD`, `POST` — браузер отправит их с чужого сайта без спроса,
  если тело «простое». Решение — ниже, по `Content-Type`.
- `OPTIONS` — это сам preflight. Его браузер отправляет автоматически
  с любого сайта, поэтому он ничего не доказывает. Без этой строки чужая
  страница, сделав `fetch` с JSON, вызвала бы касание самим preflight-запросом.
- Любой другой метод (`PUT`, `DELETE`, `PATCH`, выдуманный `PURGE`) —
  только после preflight.

```go
values := r.Header.Values("Content-Type")
if len(values) == 0 {
	return false
}
return !safelistedContentType(strings.Join(values, ", "))
```

- Нет `Content-Type` — тело «простое» (или его нет).
- Несколько строк `Content-Type` браузер не присылает. `fetch` склеил бы их
  через `, `, и так же поступаем мы. Склеенное значение не разбирается как
  тип, значит «непростое».

```go
func safelistedContentType(v string) bool {
	if len(v) > maxSafelistedContentType {   // 128 байт
		return false
	}
	for i := 0; i < len(v); i++ {
		if corsUnsafeByte(v[i]) {
			return false
		}
	}
	essence, _, _ := strings.Cut(v, ";")
	switch lowerASCII(strings.Trim(essence, " \t")) {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	}
	return false
}
```

Это повторение правила из спецификации Fetch, и важно, в какую сторону можно
ошибаться:

- ответ «простой», а браузер считает «непростым» — пропустим касание
  атакующего. Неприятно, но безопасно;
- ответ «непростой», а браузер считает «простым» — чужая страница сможет
  вызвать касание у пользователя. Это ровно T2.

Поэтому каждая строка написана так, чтобы второй ошибки не было:

- `len(v) > 128` — длиннее браузер не считает заголовок простым;
- `corsUnsafeByte` — байты, с которыми браузер тоже не считает заголовок
  простым: управляющие символы, `"`, `(`, `)`, `:`, `<`, `>`, `?`, `@`, `[`,
  `\`, `]`, `{`, `}`, DEL. Список — ровно из спецификации: лишний байт в нём
  сделал бы «непростым» то, что браузер отправит без спроса;
- `strings.Cut(v, ";")` — тип до параметров: `text/plain; charset=utf-8`
  — это `text/plain`;
- `strings.Trim(essence, " \t")` — пробелы и табуляция по краям, как
  у браузера;
- `lowerASCII` — нижний регистр **только для латиницы**. `strings.ToLower`
  превратил бы турецкую «İ» в «i», и `text/plaİn` стал бы у нас простым
  `text/plain`, хотя браузер такой тип не распознаёт и отправит preflight.
  Здесь это ошибка первого, безопасного вида, но проверка должна совпадать
  с браузером. Нашла это мутация: замена `lowerASCII` на `strings.ToLower`
  уронила тест «не-ASCII в типе».

Фаззинг-тест `FuzzPreflighted` проверяет обратное свойство: всё, что
функция признала «простым», действительно один из трёх типов.

### Отказ в preflight: `Inspect` в `decoy/decoy.go`

```go
if trap.PreflightOnly && trap.Mode == policy.Enforce && policy.IsCORSPreflight(r) {
	d.Stats.PreflightsRefused.Add(1)
	respond.RefusePreflight(w)
	return true
}
```

- `IsCORSPreflight` — `OPTIONS` с заголовком `Access-Control-Request-Method`:
  так выглядит preflight браузера. Обычный `OPTIONS` без него идёт
  в приложение.
- `trap.Mode == policy.Enforce` — в режиме наблюдения сенсор ответов
  приложения не меняет.
- `respond.RefusePreflight` пишет `204` с `nosniff` и `no-store` и без
  единого `Access-Control-Allow-*`. Нет разрешения — браузер не отправит
  сам запрос.
- `return true` — preflight не уходит в приложение. **Это главное:**
  Juice Shop на любой preflight отвечает `Access-Control-Allow-Origin: *`,
  и без этого перехвата `preflight_only` не защищал бы ни от чего.

### Касание cookie-ловушки: `checkCookies`

```go
for _, c := range r.Cookies() {
	trap, ok := p.CookieByName(c.Name)
	if !ok {
		continue
	}
	present[trap.Name] = true
	if c.Value != trap.Value && !touched[trap.Name] {
		touched[trap.Name] = true
		d.Stats.CookieTouches.Add(1)
		client := event.ClientFrom(d.trust.Resolve(r))
		if !d.recent.first(client.IP, trap.ID) {
			continue
		}
		d.emitTouch(r, client, p, trap.ID, severity(trap.Confidence), map[string]string{
			"decoy_kind": "cookie",
			"confidence": string(trap.Confidence),
		})
	}
}
```

- `r.Cookies()` — заголовок `Cookie` прислал атакующий, разбирает его
  стандартная библиотека. Размер ограничен `MaxHeaderBytes` сервера (64 КиБ),
  число cookie — пределом самой библиотеки. Cookie с недопустимым значением
  она отбрасывает — для нас это «не изменена», то есть пропуск, а не ложное
  касание.
- `p.CookieByName(c.Name)` — чужие cookie (сессия приложения и другие)
  пропускаются, не читаясь дальше.
- `present[...] = true` — cookie есть, и выдавать наживку заново не нужно.
- `c.Value != trap.Value` — изменена. Сравнение обычное: значение
  не секрет, оно одинаково у всех пользователей.
- `!touched[...]` — две копии изменённой cookie в одном запросе — одно
  касание.
- `CookieTouches.Add(1)` — счётчик растёт на каждое касание, до прореживания.
- `d.recent.first(...)` — событие только о первом касании клиента за минуту
  (ниже).
- В `data` нет значения cookie — ни исходного, ни изменённого. Правило
  проекта запрещает записывать cookie в любом виде, а в изменённое значение
  атакующий может положить что угодно.

### Прореживание: `recentTouches.first` в `decoy/recent.go`

```go
if client == "" {
	return true
}
...
if last, ok := r.seen[key]; ok && now.Sub(last) < cookieTouchWindow {
	return false
}
if len(r.seen) >= maxRecentTouches {
	for k, t := range r.seen {
		if now.Sub(t) >= cookieTouchWindow {
			delete(r.seen, k)
		}
	}
	if len(r.seen) >= maxRecentTouches {
		clear(r.seen)
	}
}
r.seen[key] = now
return true
```

- Клиент без адреса (оборванная цепочка прокси) не прореживается: без
  адреса не понять, тот же ли это клиент.
- Ключ — пара «адрес клиента, ловушка». Касание той же ловушки тем же
  клиентом в течение минуты — не событие.
- Таблица ограничена: ключи — адреса, а у атакующего их может быть много
  (IPv6). При переполнении сначала удаляются истёкшие записи, а если места
  всё равно нет — таблица очищается целиком. Направление ошибки выбрано
  намеренно: переполнение даёт **лишние** события, но не пропущенные.

### Наживка: `setBaits` и `isNavigation`

```go
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
```

- Наживка — только к ответу на открытие страницы. Картинки, скрипты,
  запросы API её не получают: `Set-Cookie` на них может помешать кэшу CDN
  у клиента.
- `Sec-Fetch-Mode` прислал клиент, но ошибка здесь безвредна: худшее —
  наживка выдана или не выдана лишний раз.

```go
secure = forwarded.HTTPS(r, d.trust.Resolve(r))
w.Header().Add("Set-Cookie", trap.SetCookie(secure))
```

- `forwarded.HTTPS` — по HTTPS ли запрос. Верит только своему TLS
  и `X-Forwarded-Proto` **доверенного** прокси. Клиент, приславший
  `X-Forwarded-Proto: https` по HTTP, `Secure` не получит.
- `w.Header().Add` — заголовок кладётся в ответ до того, как `ReverseProxy`
  скопирует заголовки приложения. Прокси **добавляет** свои к нашим,
  а не заменяет их. Сквозной тест с настоящим прокси проверяет, что у
  клиента оказываются обе cookie — наша и приложения.
- Строка `Set-Cookie` собрана один раз при разборе политики стандартным
  `http.Cookie.String()`: `Path=/; HttpOnly; SameSite=Strict`, при HTTPS —
  `Secure`. Имя и значение проверены при разборе: только
  `A-Z a-z 0-9 _ . -`, поэтому политика не может дописать `; Domain=...`.

### `Sec-Fetch-*` в событиях: `fetchFrom` в `event/event.go`

```go
func fetchValue(v string, allowed map[string]bool) string {
	switch {
	case v == "":
		return ""
	case allowed[v]:
		return v
	default:
		return fetchOther
	}
}
```

Значение от клиента попадает в событие, только если оно есть в списке
из спецификации; иначе — строка `other` из кода. Строка атакующего
в событие не попадает ни при каком значении.

### `X-Original-URL`: `isForwardingHeader` в `forwarded/outbound.go`

```go
return norm == "forwarded" ||
	strings.HasPrefix(norm, "x-forwarded-") ||
	clientIPHeaders[norm] ||
	pathOverrideHeaders[norm]
```

Одна строка в существующем механизме: заголовки из `pathOverrideHeaders`
теперь обрабатываются так же, как `X-Forwarded-*`. От недоверенного
соединения они удаляются, вариант с подчёркиванием (`X_Original_URL`)
удаляется всегда.

## Две находки при проверке

1. **Приложение одобряет CORS для всех.** Первый вариант полагался на то,
   что preflight к ловушке никто не одобрит. Но Juice Shop на любой
   preflight отвечает `Access-Control-Allow-Origin: *`, и так делают многие
   API. Тогда `fetch` с JSON с чужого сайта прошёл бы, и касание было бы
   ложным. Поэтому на preflight к ловушкам с `preflight_only` отвечает сенсор.
   Проверено в `make smoke` на настоящем Juice Shop и в Chromium.
2. **Одна правка cookie — тридцать событий.** В Chromium изменённая cookie
   на одном открытии страницы Juice Shop дала 30 событий `high`: страница,
   скрипты, стили, запросы к API — все несут cookie. Касание cookie-ловушки
   оказалось состоянием, а не действием, и появилось прореживание. После
   него — одно событие на страницу, счётчик — все 30.

## Граница доверия

От атакующего до нового кода доходят:

- метод и `Content-Type` — только сравниваются (`Preflighted`), длина
  `Content-Type` ограничена сервером и ещё раз до разбора;
- `Access-Control-Request-Method` — проверяется только на наличие;
- заголовок `Cookie` — разбирает стандартная библиотека; значения только
  сравниваются с политикой и никуда не записываются;
- `Sec-Fetch-*` — в событие только значения из списка спецификации;
- `Sec-Fetch-Mode`, `Accept` — решают только, выдать ли наживку;
- `X-Forwarded-Proto` — читается только от доверенного прокси;
- `X-Original-URL`, `X-Rewrite-URL` — удаляются, если соединение не от
  доверенного прокси.

Политика — вторая граница (T15). Из неё в ответы сайта клиента попадают
имя и значение cookie, но только из безопасного набора символов, а атрибуты
ставит сенсор.

## Что может пойти не так

- **T2 — межсайтовое срабатывание.** Закрыто для ловушек с `preflight_only`
  и для cookie-ловушек. Для ловушек без условий (`/.env`) касание может
  вызвать чужая страница, поэтому их уверенность не выше `medium`,
  а `sec_fetch` в событии покажет, что запрос межсайтовый. Остаётся:
  - захваченный поддомен может подбросить cookie (`SameSite` не защищает
    от своего сайта) — префикс `__Host-` вместе с TLS;
  - XSS на самом сайте может отправить любой запрос от имени пользователя.
  Реакции до этапа 4 нет, а там для аутентифицированных пользователей —
  только накопленный скоринг.
- **T5 — распознавание.** Ответ на preflight от сенсора отличается от ответа
  приложения на соседних путях. Принято: T2 важнее.
- **Сенсор меняет ответы приложения.** `Set-Cookie` — первое такое изменение.
  Совпадение имени с cookie приложения даст ложные касания у всех
  пользователей. Защита — проверка на стенде и понятное предупреждение
  в guide.md.
- **Пропуски.** Заголовки переопределения метода (`X-HTTP-Method-Override`)
  и нестандартные заголовки не учитываются — касание может быть пропущено,
  но не выдумано. Записано в долги.

## Как это проверено

- `policy`:
  - `TestPreflighted` — 31 случай, в том числе все способы, которыми
    `Content-Type` остаётся «простым» (регистр, пробелы, параметры);
  - `TestSafelistedLengthBoundary` — граница 128/129 байт;
  - `TestParseRejects` — теперь 53 случая, из них новые: high без
    `preflight_only`, `OPTIONS` и `post` в методах, пустой список,
    `__Host-` в имени cookie, `;` и кавычки в значении, повторы;
  - `FuzzPreflighted`;
  - `TestParseValid` проверяет готовую строку `Set-Cookie` для HTTP и HTTPS.
- `decoy`:
  - `TestPreflightOnlyTrap` — форма и `text/plain` не касание, JSON —
    касание;
  - `TestPreflightRefused` — 204 без CORS, preflight не касание, обычный
    `OPTIONS` идёт в приложение;
  - `TestPreflightObserveMode`;
  - `TestCookieBait` — 7 случаев, когда наживка выдаётся и когда нет;
  - `TestCookieBaitSecure` — `Secure` только по слову доверенного прокси;
  - `TestCookieTouch` — значение cookie не попадает в событие;
  - `TestCookieTouchDeduplicated` и `TestRecentTouchesBounded` —
    прореживание и предел таблицы.
- `event`: `TestRequestFromFetch`, золотой тест формата с `sec_fetch`.
- `forwarded`, `proxy`: `X-Original-URL` и `X-Rewrite-URL` не доходят
  до приложения; `TestHTTPS` — 9 случаев.
- `cmd/sensor`: `TestRunCrossSiteTraps` — через настоящий `ReverseProxy`
  с приложением, которое одобряет CORS для всех и ставит свою cookie.
- `make smoke` — то же против настоящих Juice Shop и VulnBank.

**Мутации** — код намеренно ломается, тест обязан упасть. 26 мутаций,
все пойманы:

| Мутация | Какой тест упал |
|---|---|
| `OPTIONS` считается «непростым» | `TestPreflighted/сам_preflight` |
| нет предела 128 байт | `TestSafelistedLengthBoundary` |
| нет проверки запрещённых байтов | `TestPreflighted/запрещённый_байт_в_параметре` |
| нет нижнего регистра | `TestPreflighted/текст_в_верхнем_регистре` |
| `strings.ToLower` вместо `lowerASCII` | `TestPreflighted/не-ASCII_в_типе` |
| high без `preflight_only` разрешён | `TestParseRejects/very_high_без_preflight_only` |
| `OPTIONS` разрешён в `methods` | `TestParseRejects/OPTIONS_в_методах` |
| методы не проверяются | `TestPreflightOnlyTrap` |
| `preflight_only` не проверяется | `TestPreflightOnlyTrap` |
| preflight не перехватывается | `TestPreflightRefused`, `TestRunCrossSiteTraps` |
| preflight перехватывается и в `observe` | `TestPreflightObserveMode` |
| сравнение cookie наоборот | `TestCookieTouch`, `TestCookieUnchanged` |
| касание на каждую копию cookie | `TestCookieTouch` |
| значение cookie в событии | `TestCookieTouch` |
| наживка поверх существующей cookie | `TestCookieBait`, `TestCookieTouch` |
| наживка не только на `GET` | `TestCookieBait/отправка_формы` |
| `Secure` по заголовку клиента | `TestHTTPS` |
| `X-Original-URL` проходит от клиента | `TestSetOutbound*` |
| `Sec-Fetch-*` без проверки значения | `TestRequestFromFetch` |
| имя cookie может начинаться с `_` | `TestParseRejects/cookie:_префикс___Host-` |
| прореживания нет | `TestCookieTouchDeduplicated` |
| граница окна включительно | `TestCookieTouchDeduplicated` |
| клиент без адреса прореживается | `TestRecentTouchesUnknownClient` |
| нет полной очистки таблицы | `TestRecentTouchesBounded` |
| нет очистки истёкших записей | `TestRecentTouchesBounded` |
| счётчик считает только записанные касания | `TestCookieTouchDeduplicated` |

Мутация «нет очистки истёкших» сначала выжила: в тесте все записи истекали
одновременно, и «удалить истёкшие» ничем не отличалось от «удалить всё».
Тест переписан на смесь старых и свежих записей.

## Проверьте руками

```bash
make dev-demo

# №8: POST с JSON — ловушка отвечает, форма — ответ Juice Shop
curl -s -X POST -H 'Content-Type: application/json' -d '{}' \
  http://127.0.0.1:8080/api/internal/v1/users/export        # {"status":"queued",...}
curl -s -X POST -d 'a=1' http://127.0.0.1:8080/api/internal/v1/users/export | head -c 80

# preflight с чужого сайта к ловушке и к обычному пути — сравните
curl -si -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST' \
  http://127.0.0.1:8080/api/internal/v1/users/export        # 204, без Access-Control-*
curl -si -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST' \
  http://127.0.0.1:8080/api/Products                        # 204, Access-Control-Allow-Origin: *

# №9: наживка на переходе по странице и касание при изменённом значении
curl -si -H 'Sec-Fetch-Mode: navigate' http://127.0.0.1:8080/ | grep -i '^set-cookie'
curl -s -o /dev/null -H 'Cookie: account_role=admin' http://127.0.0.1:8080/
curl -s -o /dev/null -H 'Cookie: account_role=admin' http://127.0.0.1:8080/   # второе — без события

# межсайтовая картинка: касание /.env с sec_fetch
curl -s -o /dev/null -H 'Sec-Fetch-Site: cross-site' -H 'Sec-Fetch-Dest: image' http://127.0.0.1:8080/.env

make dev-events | grep decoy.touch
```

В событиях должно быть:

- касание `api-export` от POST с JSON и ни одного от формы или preflight;
- одно касание `role-cookie` с `"decoy_kind":"cookie"` и без слова `admin`;
- касание `env-file` с `"sec_fetch":{"site":"cross-site","dest":"image"}`.

В браузере то же самое: откройте `http://127.0.0.1:8080/`, в инструментах
разработчика (Application → Cookies) измените `account_role` и обновите
страницу — одно событие, хотя запросов с изменённой cookie десятки.

## Вопросы для самопроверки

1. Страница атакующего содержит `<img src="https://shop.example/.env">`
   и `fetch` с JSON на ловушку с `preflight_only`. Какой из запросов даст
   касание, какой — нет, и что в событии первого поможет этапу 4 не наказать
   пользователя?

   <details><summary>Ответ</summary>

   Картинка — простой `GET`, браузер отправит его сразу, и ловушка `/.env`
   без условий запишет касание. Но в событии будет
   `sec_fetch.site: cross-site` и `dest: image` — признак, что запрос
   пришёл с чужой страницы. Поэтому у таких ловушек уверенность не выше
   `medium`. `fetch` с JSON требует preflight. На него ответит сенсор без
   разрешения, и браузер сам запрос не отправит: касания нет.

   </details>

2. Почему сенсор отвечает на preflight к ловушке сам, а не пропускает его
   в приложение? Почему не делает этого в режиме `observe`?

   <details><summary>Ответ</summary>

   Приложение может одобрять CORS для любого сайта, как Juice Shop
   с `Access-Control-Allow-Origin: *`. Тогда браузер получил бы разрешение,
   отправил бы «непростой» запрос с чужой страницы, и `preflight_only`
   ничего бы не защищал. В режиме наблюдения сенсор по смыслу режима
   не меняет ответов приложения. Касание там может оказаться межсайтовым —
   это видно по `sec_fetch`, а реакции на касания в режиме наблюдения нет.

   </details>

3. `Preflighted` может ошибиться двумя способами. Какими, чем опасна каждая
   ошибка и почему код допускает только одну?

   <details><summary>Ответ</summary>

   Назвать «простым» то, что браузер считает «непростым» — пропустим
   касание атакующего: неприятно, но безопасно. Назвать «непростым» то,
   что браузер отправит без спроса, — чужая страница сможет вызвать касание
   у пользователя, это угроза T2. Поэтому проверка консервативна:
   нестандартные заголовки не учитываются вовсе, список запрещённых байтов —
   ровно из спецификации, тип сравнивается так же, как в браузере.

   </details>

4. Администратор сменил в cookie-ловушке `value` с `customer` на `basic`.
   Что произойдёт и как было правильно?

   <details><summary>Ответ</summary>

   У всех, кто уже получил `account_role=customer`, cookie окажется
   «изменённой», и каждый такой пользователь даст касание высокой
   уверенности — массовые ложные касания. Правильно менять имя (например,
   `account_tier=basic`): cookie со старым именем сенсор просто перестанет
   проверять, а новую выдаст при следующем переходе по странице.

   </details>

5. Почему сенсор удаляет `X-Original-URL` от клиента, но не записывает
   событие? От какой атаки защищает удаление?

   <details><summary>Ответ</summary>

   IIS, Symfony, Laminas берут путь запроса из этого заголовка. Запрос
   `GET /` с `X-Original-URL: /admin` прокси и сенсор видят как `/`,
   а приложение обрабатывает как `/admin`. Так обходят запреты на пути
   в прокси и ловушки сенсора. Удаление закрывает этот обход, как и для
   `X-Forwarded-*`. Событие не пишется, потому что продукт — не WAF:
   сигнатуры атак в обычных запросах — шум, а ценность продукта в том,
   что касание ловушки не бывает случайным.

   </details>
