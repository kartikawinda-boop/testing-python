FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY openapi.yaml .

RUN groupadd -r app && useradd -r -g app app
RUN chown -R app:app /app

USER app

EXPOSE 9500

CMD ["python", "app.py"]