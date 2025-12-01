FROM python:3.12-slim

WORKDIR /app

# Instala dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copia shared primero
COPY shared /app/shared

# Instala shared como paquete
RUN pip install --no-cache-dir /app/shared

# Copia e instala dependencias del servicio
COPY gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia código del servicio
COPY gateway/ .

# Expone puerto
EXPOSE 8080

# Comando de inicio
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]