FROM python:3.12-slim as shared-base

WORKDIR /shared

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .