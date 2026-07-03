FROM python:3.10-slim-bullseye

# No native C extensions needed — the encryption service uses only
# Python stdlib crypto (hmac, hashlib, base64) plus FastAPI/uvicorn.
# libpbc-dev is not available in Bullseye apt repos and is not required.

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
