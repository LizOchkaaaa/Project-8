# Безопасная сборка и разбор проверок

Краткое руководство по архитектуре, функциям, ИИ-помощнику и запуску: [Word-документ](docs/Project-8-guide.docx).

Учебное Flask-приложение: временные заметки, пять security-проверок, независимый барьер выпуска и помощник по исправлению замечаний. `/` — заметки, `/security` — локальный просмотр готового `analysis.json`.

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

Base URL, например `https://provider.example/v1`, задаётся без `/chat/completions`; default — `https://api.openai.com/v1`. Модель задаётся явно. Для remote обязателен HTTPS; локально разрешены HTTP localhost/127.0.0.1/[::1]. URL берётся только из доверенной env-конфигурации, никогда из отчётов.

Один `POST <base>/chat/completions`, Bearer auth, только поля **model/messages**. Без Responses API, SDK и специфических optional parameters. Redirects отключены, timeout 15 секунд, максимум запроса 128 КиБ, прочитанного ответа 256 КиБ. У провайдеров различаются доступные модели и качество соблюдения JSON-инструкции.

Allowlist запроса: внутренние IDs, severity/scanners, идентификаторы пакетов/версий/aliases, исправленные версии из evidence. Secret, Match, код, описания сканеров, пути файлов и target URL не отправляются. У Gitleaks в запросе остаются только group ID, severity/scanner. Вход объявлен недоверенными данными. JSON-ответ проверяется: все известные IDs ровно один раз, order 1..N, типы/длины reason/action. Модель может менять порядок внутри одной категории; обязательный приоритет сохраняется. Номера версий в модельном тексте запрещены: UI показывает версии отдельно из evidence с оговоркой об их применимости.

Без ключа/модели, при timeout/401/429/redirect, сетевой ошибке, неправильном JSON/IDs/размере ответ заменяется **явно обозначенным deterministic fallback**. Он не выдаётся за модель. Модель всегда advisory и не меняет gate. Ключ только в среде процесса/CI secrets, никогда во frontend или analysis.json.

### Просмотр в приложении

На `/security` выберите `analysis.json` через file picker. Browser File API читает файл локально, без отправки серверу и модельных запросов. Все значения выводятся через `textContent`; evidence URL остаются текстом. Внешние same-origin CSS/JS работают со строгой CSP без unsafe-inline/eval. Есть светлая/тёмная тема, клавиатурный фокус, reduced motion. Импортированный `passed` — содержимое выбранного файла, не разрешение настоящего выпуска.

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

Результаты зависят от актуальности базы уязвимостей и внешних сервисов; unknown блокируется консервативно. Файл анализа не доказывает своё происхождение. Нет постоянного хостинга, авторизации, внешнего хранилища и автономного изменения кода моделью. Docker/Trivy/ZAP и реальный модельный API требуют отдельного запуска в подходящей среде; unit-тесты и synthetic demo его не заменяют.


