FROM python:3.12-alpine

# iptables is used by the SSH access controller (needs NET_ADMIN + host network).
RUN apk add --no-cache iptables iptables-legacy tzdata

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY nasgate ./nasgate

ARG VERSION=dev
ARG BUILD_DATE=""
ENV NASGATE_DATA_DIR=/data \
    NASGATE_PORT=8787 \
    NASGATE_VERSION=$VERSION \
    NASGATE_BUILD_DATE=$BUILD_DATE \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=60s --timeout=5s CMD wget -qO- http://127.0.0.1:${NASGATE_PORT}/health || exit 1

CMD ["python", "-m", "nasgate.main"]
