FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml ./
COPY packages/contracts ./packages/contracts
COPY services ./services
RUN pip install --no-cache-dir '.[postgres]'
COPY demo/fixtures ./demo/fixtures
RUN useradd --create-home --uid 10001 agentguard
USER agentguard
EXPOSE 8000
CMD ["uvicorn", "agentguard_backend.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
