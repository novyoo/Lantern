FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iproute2 procps iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server/ /app/server/
WORKDIR /app/server

CMD ["sh", "-c", "alembic upgrade head && python seed.py && uvicorn main:app --host 0.0.0.0 --port 8000"]
