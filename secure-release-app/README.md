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
