FROM python:3.11-alpine

RUN apk add --no-cache curl

LABEL org.opencontainers.image.title="mcp-oauth-gateway" \
      org.opencontainers.image.description="Remote MCP server with standard OAuth 2.0 (PKCE + dynamic client registration) for Gemini/Claude" \
      org.opencontainers.image.version="1.0.0"

WORKDIR /app
COPY app.py /app/app.py

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f -s http://127.0.0.1:8080/.well-known/oauth-authorization-server > /dev/null || exit 1

USER nobody
CMD ["python3", "/app/app.py"]
