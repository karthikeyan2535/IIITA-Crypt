FROM python:3.10-slim-bullseye

# Install C-dependencies for pyabe/pypairing
RUN apt-get update && apt-get install -y \
    build-essential \
    libgmp-dev \
    libpbc-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port based on system-state.json plan
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
