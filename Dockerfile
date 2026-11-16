FROM python:3.13-slim

LABEL org.opencontainers.image.description="Fake eWeLink cloud that logs and talks to Sonoff devices"
LABEL org.opencontainers.image.source=https://github.com/lucasmaurice/ewelink-fake

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY server.py /app/server.py

USER 1000:1000
EXPOSE 8080 8443

ENTRYPOINT ["python3", "/app/server.py"]
