# Безопасная сборка и разбор проверок

Краткое руководство по архитектуре, функциям, ИИ-помощнику и запуску: [Word-документ](docs/Project-8-guide.docx).

Учебное Flask-приложение: временные заметки, пять security-проверок, независимый барьер выпуска и помощник по исправлению замечаний. `/` — заметки, `/security` — помощник с загрузкой отчётов, модельным API и учебными примерами.

## Запуск

Python 3.13; команды из корня репозитория. PowerShell:

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m app.main
```

Откройте http://127.0.0.1:8000. API: `GET/POST /api/items`, `DELETE /api/items/<id>`, `GET /health`. До 200 символов на заметку, до 1000 заметок, запрос до 16 КиБ. Заметки общие, без учётных записей, в памяти **одного** процесса, исчезают при перезапуске. Это открытый учебный API: не помещайте сюда секреты и персональные данные.

Docker использует Python 3.13, непривилегированного пользователя и один Gunicorn worker:

```sh
docker build -t secure-release-app .
docker run --rm -p 127.0.0.1:8000:8000 secure-release-app
```

## Разбор отчётов в браузере

Откройте `http://127.0.0.1:8000/security`. Начните с файлов своего CI или сравните два учебных результата: с замечанием и после исправления. В обоих примерах анализируются синтетические отчёты, без запуска сканеров и модели.

Для своего разбора загрузите по одному JSON от Gitleaks, Bandit, pip-audit, Trivy и ZAP. Можно начать с неполного набора: система покажет доступные замечания и отметит недостающие данные. Для серверной формы без JavaScript откройте `/reports/local`; в ней также принимаются имена из CI: `sast.json`, `sca.json` и `report.json`.

В левой панели доступны рабочие разделы и журнал. Загрузка на сервер, получение отчётов по HTTP и разбор через MCP создают запись как при допуске, так и при блокировке. Фильтр «Пройдены» оставляет только разборы, прошедшие порог. Открытие записи показывает результат с исходной ревизией политики, без повторного анализа и без запроса к модели. Учебные примеры и импорт готового `analysis.json` в браузер отдельно в журнал не записываются. До появления журнала приложение не хранило результаты; старые выгрузки доступны через «Открыть JSON».

В журнале остаются нормализованные замечания, включая пути файлов и рекомендации, но не необработанные входные отчёты. История хранится в `instance/report-history.sqlite3`, конфигурация — в том же каталоге. Для отдельного стенда, резервного копирования или тестирования можно задать абсолютный `PROJECT8_INSTANCE_DIR`; для Docker подключите постоянный том с доступом на запись. Доступ к рабочему каталогу предоставляйте только владельцу стенда.

В `/admin#model-profile` настраивается профиль модели: базовый адрес совместимого API, имя модели, время ожидания и ключ. Адрес, имя и тайм-аут переживают перезапуск; ключ профиля хранится только в памяти процесса и после перезапуска вводится заново. В рабочем экране выберите сохранённый профиль или разовое подключение и подтвердите передачу сводки показанному провайдеру. Без согласия разбор полностью локальный. В той же админке настраиваются источники готовых JSON, пороги политики, сетевые лимиты и отображается состояние MCP.

Модель необязательна. Для одного запроса укажите совместимый базовый URL, имя модели и API-ключ. Провайдер получает идентификаторы групп, сканеры, уровни и фиксированные категории, но не пути, содержимое файлов и названия пакетов. При ошибке остаются локальные рекомендации. Политика выпуска от ответа модели не зависит.

Загрузка файлов и вызов API разрешены только с loopback-адреса и локальным Host; запрос защищён случайным токеном страницы. На удалённом стенде форма с ключом скрыта и API анализа возвращает 403. Это локальный учебный помощник без публичной авторизации. Отчёты временно передаются локальному Python-приложению и удаляются после обработки; секретные фрагменты, исходный код и пути в модель не передаются.

Готовый analysis.json по-прежнему можно открыть только в браузере, без отправки серверу. Результат анализа скачивается кнопкой «Скачать JSON», Word — ссылкой «Документация» или через `/documentation`.

## Локальные проверки

После активации venv (или с полным путём к его Python):

```sh
python -m pytest -q --junitxml=test-results/junit.xml --alluredir=allure-results
python -m ruff check .
python -m ruff format --check .
python -m bandit -r app security_assistant scripts -ll
python -m pip_audit -r requirements.txt
```

Тесты коллеги и Allure сохранены. `pytest -q` тоже работает из корня благодаря `pytest.ini`. Для перенаправления русского вывода в Windows используйте `python -X utf8 ...`, если терминал выбирает другую кодировку. Allure CLI для построения HTML устанавливается отдельно и не нужен приложению.

## Помощник

CLI использует только stdlib Python. В reports нужны пять JSON-файлов:

| Имя | Формат |
| --- | --- |
| `gitleaks.json` | Gitleaks JSON array; создавайте с `--redact=100` |
| `bandit.json` | results, errors и metrics обработанного кода |
| `pip-audit.json` | object с dependencies, vulns, aliases, fix_versions |
| `trivy.json` | SchemaVersion 2, container_image, Results os-pkgs/lang-pkgs |
| `zap.json` | traditional JSON с @version, site, alerts, instances |

Архивы не принимаются. Лимиты: 8 МиБ на файл и 2000 замечаний суммарно. Missing/invalid/пустой файл, неверная структура, skipped dependency не означают success. Пустой array Gitleaks допустим; остальные отчёты должны подтвердить проверку кода/компонентов/сайта. Неизвестный будущий формат закрывает допуск до адаптации парсера.

```sh
python -m security_assistant --reports reports --output analysis --offline
python -m security_assistant --reports reports --output analysis --gate
```

Первая команда без сети. Вторая выполняет policy **без модели**: exit 0 — пройдена, 1 — выпуск запрещён, 2 — ошибка policy/pipeline/сохранения. Обычный advisory CLI возвращает 0 при сохранённом разборе, даже если внутри указан **blocked**: его exit code нельзя использовать для допуска. Без `--pipeline pipeline.json` область проверки — только `reports_only`, без подтверждения jobs CI.

Выход: `analysis.json` и `analysis.md`. Общие CVE/GHSA aliases одной библиотеки, версии и ecosystem объединяются между pip-audit/Trivy; имена PyPI нормализуются. Все первичные IDs, occurrences и evidence locations сохраняются. Разные пакеты/версии/ecosystems не смешиваются. Severity группы максимальная. Приоритет: secrets → critical → high → unknown → medium → low → info.

### Совместимый модельный API

В доверенной среде задайте **OPENAI_API_KEY**, **OPENAI_BASE_URL**, **OPENAI_MODEL**, затем:

```sh
python -m security_assistant --reports reports --output analysis
```

`.env.example` содержит шаблон без секретов. CLI не загружает `.env` автоматически: задайте переменные в окружении процесса. В PowerShell адрес и модель можно задать как `$env:OPENAI_BASE_URL = 'https://provider.example/v1'` и `$env:OPENAI_MODEL = 'имя-модели'`. Чтобы ввести ключ без отображения на экране и сохранения в истории команд:

```powershell
$apiSecret = Read-Host 'API key' -AsSecureString
$env:OPENAI_API_KEY = [System.Net.NetworkCredential]::new('', $apiSecret).Password
```

После работы удалите ключ из текущего процесса командой `Remove-Item Env:OPENAI_API_KEY`.

Base URL, например `https://provider.example/v1`, задаётся без `/chat/completions`; default — `https://api.openai.com/v1`. Модель задаётся явно. Для remote обязателен HTTPS; локально разрешены HTTP localhost/127.0.0.1/[::1]. В CLI URL берётся из env, в веб-форме — из настроек, явно введённых локальным пользователем; никогда из отчётов.

Один `POST <base>/chat/completions`, Bearer auth, только поля **model/messages**. Без Responses API, SDK и специфических optional parameters. Redirects отключены, тайм-аут CLI и разового запроса 15 секунд, тайм-аут сохранённого профиля настраивается, максимум запроса 128 КиБ, прочитанного ответа 256 КиБ. У провайдеров различаются доступные модели и качество соблюдения JSON-инструкции.

Allowlist запроса: внутренние IDs групп, severity, scanners и фиксированная категория. Названия пакетов и версии остаются в локальном результате. Secret, Match, код, описания сканеров, пути файлов и target URL не отправляются. У Gitleaks в запросе остаются только group ID, severity/scanner. Вход объявлен недоверенными данными. JSON-ответ проверяется: все известные IDs ровно один раз, order 1..N, типы/длины reason/action. Модель может менять порядок внутри одной категории; обязательный приоритет сохраняется. Номера версий в модельном тексте запрещены: UI показывает версии отдельно из evidence с оговоркой об их применимости.

Без ключа/модели, при timeout/401/429/redirect, сетевой ошибке, неправильном JSON/IDs/размере ответ заменяется **явно обозначенным deterministic fallback**. Он не выдаётся за модель. Модель всегда advisory и не меняет gate. В CLI ключ берётся из среды процесса/CI secrets. В разовом режиме веб-формы ключ очищается после отправки и не попадает в хранилище браузера или analysis.json.

### Просмотр в приложении

На `/security` выберите `analysis.json` через file picker. Browser File API читает файл локально, без отправки серверу и модельных запросов. Все значения выводятся через `textContent`; evidence URL остаются текстом. Внешние same-origin CSS/JS работают со строгой CSP без unsafe-inline/eval. Есть светлая/тёмная тема, клавиатурный фокус, reduced motion. Импортированный `passed` — содержимое выбранного файла, не разрешение настоящего выпуска. Шрифт Onest хранится локально в app/static/fonts вместе с лицензией OFL; интерфейс не обращается к сервисам шрифтов.

## Policy и CI

`.security/policy.yml` — **JSON-compatible YAML**, читаемый stdlib `json`. PyYAML используется только dev-тестом workflow, runtime его не импортирует. Policy исполняется в scanner jobs и финальном gate:

| Проверка | Запрет |
| --- | --- |
| Gitleaks | Любой secret |
| Bandit | Medium и выше |
| pip-audit | High/critical/unknown (обычно severity отсутствует) |
| Trivy | High/critical/unknown, включая **unfixed** |
| ZAP | Medium/high/unknown |
| Полнота | Missing/invalid reports, operational failure, failed/skipped/cancelled обязательная job |

```text
Ruff + pytest + Gitleaks + Bandit + pip-audit (параллельно)
                    ↓ все успешны
             build → image-unreleased artifact
                    ↓
                 Trivy + ZAP
                    ↓
   security-gate (always: все обязательные jobs + policy)
                    ↓ только success
   deploy ephemeral учебного стенда → HTTP/API smoke → cleanup

advisory (always) → доступные reports текущего run → security-analysis
```

Ранние дешёвые сканы и тесты дают независимую диагностику. Затем Trivy проверяет образ, ZAP — HTTP/CSP запущенного сервиса. ZAP baseline пассивный, не полный аудит API; exit 1/2 означает findings/WARN, severity определяет policy, exit 3+ — operational failure. Отчёты загружаются через `always()`, ошибки запуска не превращаются в clean.

Gate проверяет каждый needs: lint/tests/secret-detection/sast/sca/build/scan-image/dast. Advisory собирает только текущий run, отражает missing/skipped и пишет summary, без PR-комментариев. Ошибка модели не блокирует чистый gate. Модельный secret передаётся только на push main или manual **main**; любые PR и manual других веток используют fallback. `pull_request_target` отсутствует. В настройках GitHub при необходимости задайте secret `OPENAI_API_KEY`, variables `OPENAI_BASE_URL`, `OPENAI_MODEL`.

Deploy — отдельная job **после gate**. Она скачивает тот же tar, проверяет SHA256, загружает образ без пересборки, запускает на loopback GitHub runner, проверяет `/`, `/security`, `/health` и create/read/delete API. Артефакт `deployment-evidence` содержит commit, image ID, checksum, smoke и логи; контейнер останавливается в cleanup. Это **ephemeral учебный стенд**, не постоянный хостинг. Наличие `image-unreleased` до gate не разрешает выпуск.

Для запрета merge владелец репозитория должен отдельно сделать `Security gate (required release barrier)` required check в branch protection/ruleset. Workflow обеспечивает зависимость deploy, но не меняет административные настройки.

## Воспроизводимый отказ и исправление

```sh
python scripts/security_demo.py --output demo-output
```

Скрипт создаёт временную функцию с `subprocess.run(command, shell=True)`, **не исполняет её**, реально запускает Bandit и использует тот же parser+policy. Первая стадия даёт `BLOCK`, после удаления опасной функции — `PASS`. В `demo-output/fail` и `fixed` сохраняются source, report Bandit и analysis. Остальные четыре отчёта — явно обозначенные **synthetic clean fixtures**. Это локальная проверка SAST+policy, не полный secure release.

В manual workflow выберите `security_demo=fail`: реальный SAST сканирует пример, Bandit и gate отказывают, build/deploy пропускаются, advisory объясняет отказ. Затем `security_demo=fixed`: пример исправлен, но полный выпуск зависит от **всех реальных** сканеров, тестов и сборки. Сохраните URL обоих runs и успешное deployment evidence. Не называйте remote pipeline зелёным до фактического выполнения.

## Ограничения

Результаты зависят от актуальности базы уязвимостей и внешних сервисов; unknown блокируется консервативно. Файл анализа не доказывает своё происхождение, свежесть или покрытие текущего commit/image. Нет постоянного хостинга, пользовательских аккаунтов, внешнего хранилища и автономного изменения кода моделью. Админ-панель и MCP доступны локально, имеют разные токены. Docker/Trivy/ZAP и реальный модельный API требуют отдельного запуска в подходящей среде; unit-тесты и synthetic demo его не заменяют.

## Админ-панель и отчёты через HTTP API

Откройте `/admin` на localhost/127.0.0.1. Для каждого из пяти сканеров можно включить источник готового JSON-отчёта и указать URL. Кнопка «Получить отчёты и разобрать» на `/security` выполняет GET к настроенным источникам и передаёт результат тому же сервису анализа, который использует загрузка файлов. Это получение готового отчёта, а не запуск сканера.

Разрешён публичный HTTPS либо явно настроенный loopback HTTP. Нет редиректов, ambient proxy и сжатия; принимается только HTTP 200 application/json до 8 МиБ на отчёт. Все DNS-адреса проверяются; сокет закрепляется за проверенным IP с исходными TLS SNI и Host. URL не может содержать секрет, query, fragment или userinfo. Ошибка/отключённый источник/неверный отчёт означают `scans.status=error` и `blocked`, без подстановки clean.

Для Bearer выберите «Bearer из окружения» и задайте в окружении сервера ровно соответствующую переменную: `PROJECT8_CONNECTOR_GITLEAKS_TOKEN`, `PROJECT8_CONNECTOR_BANDIT_TOKEN`, `PROJECT8_CONNECTOR_PIP_AUDIT_TOKEN`, `PROJECT8_CONNECTOR_TRIVY_TOKEN`, `PROJECT8_CONNECTOR_ZAP_TOKEN`. В JSON настроек сохраняется только имя. Значения не выдаются API; отражённый credential приводит к отклонению отчёта.

Порог серьёзности меняется только для runtime-анализа. Все пять отчётов обязательны, secrets/critical/unknown всегда блокируются. Runtime-настройки не переписывают CI `.security/policy.yml`. Замечания ниже порога дают оранжевый статус «Порог пройден — нужна проверка», а не «чисто».

Настройки сохраняются атомарно в игнорируемом `instance/runtime-config.json`. `If-Match` защищает от конфликтов: HTTP 409 оставляет правки в форме, перезагрузка требует подтверждения. Повреждённый config блокирует анализ и не заменяется defaults. `runtime_revision` в результате позволяет обнаружить устаревшую policy.

| API | Контракт |
|---|---|
| GET `/api/security/config` | `{revision,config,effective_policy,mcp}` без значений credentials |
| PUT `/api/security/config` | полный config и `If-Match: revision`, новая revision или 409 |
| GET/PUT/DELETE `/api/security/model-profile` | Профиль модели; в ответе только публичные поля, revision и наличие ключа |
| GET `/api/security/history` | Защищённый журнал: фильтр gate=all/pass/fail, offset, до 25 записей и next_offset |
| GET `/api/security/history/<id>` | Сохранённый результат в формате analysis.json |
| GET `/api/security/policy` | `{revision,effective_policy}` |
| POST `/api/security/tools/run` | ровно `{}`, общий анализ с `duration_ms` и `tool_fetch` |

Admin API требует loopback peer, корректный Host/порт, отдельный `X-Assistant-Token` страницы и точный Origin при его наличии. Token нельзя передать в URL. Ошибки новых маршрутов: `{error:{code,message}}`; старый upload сохраняет строковый error.

По умолчанию connect=3 с, read-idle=5 с, общий бюджет получения=15 с, workers=3. Допустимые диапазоны — 1–3, 1–5, 1–15 и 1–3 соответственно. Один полный анализ одновременно для upload/API/MCP; занятость возвращает 429. Поддерживается один процесс сервера. Системный DNS не отменяется: caller ограничивает ожидание, до трёх resolver jobs могут оставаться занятыми; Python CPU, приём WSGI body и модельный API не имеют общей жёсткой гарантии wall-clock.

## MCP-сервер приложения

Перед запуском задайте независимый `PROJECT8_MCP_TOKEN`. Пустое или некорректное значение отключает `/mcp`. `.env.example` — только справочник; автоматически переменные из файла не читаются. Для ввода в PowerShell без отображения и истории значения:

```powershell
$mcpSecret = Read-Host 'MCP token' -AsSecureString
$env:PROJECT8_MCP_TOKEN = [System.Net.NetworkCredential]::new('', $mcpSecret).Password
python -m app.main
```

Подключение: `http://127.0.0.1:8000/mcp`, Streamable HTTP, `Authorization: Bearer <token>`. Поддерживается протокол `2025-11-25`, JSON responses без SSE и sessions; отсутствие MCP-Protocol-Version использует совместимость `2025-03-26`. Инициализация, ping, initialized notification, tools/list и tools/call реализованы. POST требует application/json и Accept для application/json + text/event-stream. Notifications возвращают 202, авторизованный GET — 405.

| Tool | Аргументы |
|---|---|
| `get_policy` | `{}` |
| `analyze_reports` | `{reports:{<scanner>:<сырой JSON сканера>}}`, 1–5 известных keys |
| `run_tools` | `{}` — получение всех настроенных источников |

Tools не принимают URL, пути к файлам, команды, policy, готовый gate или настройки модели. Tool calls используют общий сервис и offline advisory. Результат содержит одинаковый JSON в `structuredContent` и text. `blocked` — успешный анализ с `isError:false`; ошибки исполнения отделены от JSON-RPC ошибок.

MCP имеет собственную Bearer-авторизацию, не принимает page token, проверяет loopback peer и Host/порт. Origin при наличии должен совпасть целиком; можно задать точные дополнительные origins в `PROJECT8_MCP_ALLOWED_ORIGINS`, без wildcard/null. Forwarded-заголовки не используются. **Не публикуйте этот локальный режим через прокси.** OAuth discovery, stdio и MCP-клиент для чужих серверов не реализованы. Совместимость заявлена для локальных HTTP MCP-клиентов с настраиваемыми headers; проверен официальный Python SDK mcp 2.3.0, установленный только в audit venv.

## Интерфейс и локальная проверка расширения

В новом профиле браузера используется светлая тема. Переключатель в боковой панели сохраняет выбор темы; отчёты и ключи не записываются в browser storage. Статусы допуска подписаны текстом, анимации учитывают reduced motion. Данные отчётов выводятся через textContent под строгой CSP.

Локально прошло 225 pytest-тестов, Ruff и Bandit для app/security_assistant. Браузер проверил сохранение и конфликт config, получение пяти HTTP-отчётов, отказ на плохом JSON, обе темы, 360–1440 px, анимацию и reduced motion. Официальный MCP SDK smoke проверяет handshake и все три tools; без установленного SDK этот один необязательный тест пропускается. Реальные внешние API и полный Docker CI этим набором не подтверждены.

Синтетические измерения на этой машине, по три запуска: пять GET с задержкой 120 мс каждый — медиана 656 мс с workers=1 и 276 мс с workers=3. Анализ без сети — 27 мс для чистых отчётов и 392 мс для 2000 отдельных замечаний. Это проверка ограниченного локального сценария; время выполнения самих сканеров не измерялось.


