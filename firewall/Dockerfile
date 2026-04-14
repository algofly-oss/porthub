FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y nftables && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

VOLUME ["/state"]

CMD ["/bin/bash", "-lc", "chmod +x /app/entrypoint.sh && /app/entrypoint.sh"]
