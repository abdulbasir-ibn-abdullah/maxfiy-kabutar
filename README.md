# VOID — Ephemeral E2EE Chat

Zero-persistence, end-to-end encrypted chat. Nothing is stored anywhere.

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Then open: http://localhost:8000

## Architecture

```
Browser A                   Server (RAM only)              Browser B
────────                    ─────────────────              ────────
PBKDF2(pass+roomId)→key     rooms: dict{}                  PBKDF2(pass+roomId)→key
encrypt(text, key)→ct  →→→  relay ct as-is  →→→           decrypt(ct, key)→text
                            (never sees plaintext)
```

## Security notes

- **Encryption**: AES-256-GCM with unique IV per message
- **Key derivation**: PBKDF2-SHA256, 200,000 iterations, salt = roomId + constant
- **Server auth**: Argon2id password hash (verification only, key never sent to server)
- **No storage**: No DB, no files, no logs, no cookies
- **Message TTL**: 60 seconds after delivery, then wiped from RAM
- **Room TTL**: Destroyed when all users leave; 10-min timeout if no 2nd user joins
- **Transport**: WebSocket (use HTTPS/WSS in production behind nginx/caddy)

## Production deployment (example with nginx)

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```
