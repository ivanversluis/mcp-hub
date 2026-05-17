FROM python:3.12-alpine AS runtime

RUN apk add --no-cache nmap ca-certificates \
    && update-ca-certificates \
    && pip install --no-cache-dir mcpo

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN adduser -D -u 1000 mcpuser
USER mcpuser

ENTRYPOINT ["mcp-nmap"]
