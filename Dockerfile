FROM python:3.12-slim

WORKDIR /app

COPY list_server.py /app/

EXPOSE 8001

CMD ["python3", "list_server.py"]
