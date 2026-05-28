# Skaner sieci LAN - kontener oparty na Alpine 3.21
FROM alpine:3.21

# Python + YAML + Nmap z bazą skryptów NSE
RUN apk add --no-cache \
    python3 \
    py3-yaml \
    nmap \
    nmap-scripts \
    tzdata \
 && ln -sf /usr/share/zoneinfo/Europe/Warsaw /etc/localtime

WORKDIR /app

COPY src/ ./src/

# Katalog na wyniki i baseline (montowany jako volume w produkcji)
RUN mkdir -p /data /tmp/scans

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Konfiguracja idzie z hosta przez bind-mount: -v $(pwd)/config.yaml:/app/config.yaml
CMD ["python3", "src/main.py"]
