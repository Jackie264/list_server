FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY list_server.py /app/

EXPOSE 8001

CMD ["python3", "list_server.py"]
