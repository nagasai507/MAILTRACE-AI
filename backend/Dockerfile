FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

WORKDIR /app
COPY requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt

COPY app ./app
COPY migrations ./migrations
COPY wsgi.py seed.py ./

RUN useradd --create-home --shell /usr/sbin/nologin appuser
USER appuser
EXPOSE 5000

CMD ["sh", "-c", "flask --app wsgi db upgrade && python seed.py && gunicorn -w 4 -k gthread --threads 4 -b 0.0.0.0:5000 wsgi:app"]
