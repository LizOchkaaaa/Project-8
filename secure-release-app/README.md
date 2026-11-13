# secure-release-app



## Эндпоинты
- `GET /health` — проверка живости
- `GET /api/items` — список заметок
- `POST /api/items` — `{"text": "..."}`, до 200 символов


```bash
python -m venv .venv && source .venv/bin/activate   
pip install -r requirements-dev.txt
pytest
python -m app.main            # http://127.0.0.1:8000
```


```bash
docker build -t secure-release-app .
docker run --rm -p 8000:8000 secure-release-app
curl http://localhost:8000/health
```

### Для Лизы


- `Проверка ввода`: принимается только JSON-объект, поле text должно быть непустой строкой не длиннее 200 символов, иначе ответ 400
- `Лимиты:` тело запроса не больше 16 КБ (иначе 413), не больше 1000 заметок (иначе 507)
- `Заголовки:` X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Referrer-Policy, Cache-Control: no-store. Они для проверки ZAP
- `Безопасный запуск:` без debug=True, локально слушает 127.0.0.1

#### По докеру

- `Образ` на базе python:3.12-slim (меньше пакетов, меньше уязвимостей для Trivy)
- `Зависимости` ставятся отдельным слоем, что ускоряет повторные сборки
- `Приложение` запускается не от root (пользователь appuser)
- `Запуск` через gunicorn на порту 8000, а не встроенным сервером Flask
- `HEALTHCHECK` раз в 30 секунд обращается к /health
- `.dockerignore` не пускает в образ тесты, .git, .env и прочее лишнее


##### По тестам

- `15 тестов`
- рабочие эндпоинты
- добавление и получение заметок
- отказ на некорректные данные (пустой текст, не строка, не JSON, слишком длинный текст, слишком большой запрос)
- ответы 404 и 405
- наличие заголовков безопасности