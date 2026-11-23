# Hardened Non-Root Container Image for ASTRA API & Worker (SEC-38)
FROM python:3.13-slim

RUN groupadd -g 10001 astra && useradd -u 10001 -g astra -m -s /usr/sbin/nologin astra

WORKDIR /app
COPY apps/ /app/apps/
COPY integrations/ /app/integrations/
COPY ml/ /app/ml/
COPY packages/ /app/packages/
COPY docs/ /app/docs/
COPY scripts/ /app/scripts/
COPY LICENSE THIRD_PARTY_NOTICES.md /app/

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ASTRA_EXECUTION_POLICY=local-no-egress

USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "apps.api.astra.seed_demo"]
