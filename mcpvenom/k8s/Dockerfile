FROM python:3.12-slim AS builder

WORKDIR /build
COPY mcpvenom/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

LABEL org.opencontainers.image.title="mcpvenom" \
      org.opencontainers.image.description="MCP Red Teaming / Security Scanner for Kubernetes" \
      org.opencontainers.image.source="https://github.com/tms/agentsmith"

RUN groupadd -r scanner && useradd -r -g scanner -s /sbin/nologin scanner

COPY --from=builder /install /usr/local
COPY mcpvenom/ /app/mcpvenom/

WORKDIR /app
USER scanner

ENTRYPOINT ["python", "-m", "mcpvenom"]
CMD ["--k8s-discover", "--verbose"]
