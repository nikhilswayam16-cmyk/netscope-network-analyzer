FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
RUN pip install --no-cache-dir .

EXPOSE 10000
CMD ["sh", "-c", "uvicorn netscope.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
