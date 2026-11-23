FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MAZAGI_DATA_DIR=/data

# Runtime toolchains used by uploaded user projects (Python, Node.js, PHP).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg gosu build-essential python3-dev git pkg-config libpq-dev default-libmysqlclient-dev libjpeg-dev zlib1g-dev libxml2-dev \
      libffi-dev libssl-dev php-cli php-curl php-mbstring php-xml php-zip php-intl \
      php-mysql php-pgsql php-sqlite3 php-gd php-bcmath php-soap php-opcache composer \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
       | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
       > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin mazagi \
    && mkdir -p /data \
    && chown mazagi:mazagi /data \
    && chmod 755 /app

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python", "railway_start.py"]
