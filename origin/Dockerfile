FROM python:3.12-slim
WORKDIR /app
# Only the origin's runtime deps (kept minimal & pinned).
RUN pip install --no-cache-dir fastapi==0.115.6 "uvicorn[standard]==0.34.0"
COPY origin/ ./origin/
EXPOSE 8000
CMD ["uvicorn", "origin.app:app", "--host", "0.0.0.0", "--port", "8000"]
