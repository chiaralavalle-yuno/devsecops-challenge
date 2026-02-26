FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV PORT=5003
EXPOSE 5003

CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "1", "--timeout", "30", "app:app"]
