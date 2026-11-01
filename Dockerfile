FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && groupadd --gid 10001 vault \
    && useradd --uid 10001 --gid vault --no-create-home vault \
    && mkdir /state && chown vault:vault /state
COPY --chown=vault:vault src ./src
USER vault
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
ENTRYPOINT ["python", "-m", "aegisvault.cli", "--state", "/state/vault"]
CMD ["serve", "--host", "0.0.0.0"]
