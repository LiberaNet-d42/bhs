FROM python:3.12-slim

# Empêche Python d'écrire des fichiers .pyc et active le mode unbuffered pour les logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

WORKDIR /app

# Création d'un utilisateur non-root pour la sécurité
RUN adduser --disabled-password --gecos "" appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app

# Installation des dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie des sources de l'application
COPY app/ ./app/

# Bascule sur l'utilisateur non-privileged
USER appuser

EXPOSE 5000

# Lancement avec Gunicorn (WSGI de production)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "2", "--timeout", "30", "app.main:app"]