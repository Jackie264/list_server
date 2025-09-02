FROM python:slim

EXPOSE 8001

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/list_server.py .
COPY style /style/
ENV FILE_SERVER_ROOT="/feeds_data"
ENV DOMAIN_FOOTER_INFO_JSON='{}'
RUN chmod +x list_server.py

CMD ["python3", "list_server.py"]
