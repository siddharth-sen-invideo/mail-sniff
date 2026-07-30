# Mail Sniff - container for free always-on hosting (Render / Koyeb / Fly / etc.)
FROM python:3.11-slim

# system tools the scraper uses: curl (TLS-1.3 + bot-wall fallback) and whois
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl whois ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# hosts inject the port via $PORT; bind all interfaces
ENV PORT=8100
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8100}"]
