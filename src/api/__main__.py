"""`python -m src.api` — serve on 127.0.0.1:8000. Loopback only; this is a local desktop application."""

import uvicorn

from src.api.app import HOST

if __name__ == "__main__":
    uvicorn.run("src.api.app:app", host=HOST, port=8000)
