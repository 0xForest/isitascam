# Architecture

The web app and optional WhatsApp bridge share one FastAPI service. Checks run in memory for the duration of a request. There is no database.

## How a check works

1. Both clients post text to `/assess` with a matching `Origin` (12,000-byte limit). They request NDJSON for progress updates. An empty `pending` list marks the final result. Other clients can request a single JSON response.
2. Local rules score the wording. Reputation services check the first eligible link in parallel. A provider returning no match does not establish safety.
3. Cloudflare supplies an existing page capture or, if enabled, scans the homepage. The app records which page was captured. It never opens the submitted site directly.
4. OpenRouter assesses the wording and available evidence. Website review needs HTML and a screenshot from the same capture. If capture fails, the message can still be assessed. The service validates quoted evidence and combines the findings with independent warnings.
5. Both clients show the assessment and recovery options. Reported payments change the advice independently of the verdict.

## Source guide

| To change | Start here |
| --- | --- |
| Request handling and progress | `app.py` |
| Local checks and verdicts | `assessment.py` |
| Reputation providers and scan submissions | `reputation.py`, `enrichment_http.py`, `background_scans.py` |
| Cloudflare captures | `urlscanner.py` |
| AI instructions and validation | `PHISHING_PROMPT.md`, `openrouter.py` |
| Shared advice and recovery | `guidance.py`, `static/recovery.json` |
| Web and WhatsApp clients | `templates/`, `static/`, `whatsapp/` |
| Automated tests | `tests/` |

## Data sharing

Hostname checks use DNS, reputation, certificate history and registration data. Configured URL providers receive the first eligible URL, including its query string. VirusTotal may share new submissions with its community. urlscan.io submissions request private visibility. New Cloudflare scans request unlisted visibility and may be accessible to anyone with the scan ID.

AI checks send the submitted text, selected evidence and any screenshot to OpenRouter and its model provider. Website review needs an image-capable model and a route supporting the configured privacy settings. Timing logs can include client IPs or WhatsApp numbers. Enabling `LOG_AI_RESPONSES` can also log submitted wording. [Provider settings](.env.example)

## Deployment and WhatsApp

Use one Uvicorn worker. Behind a reverse proxy, set `ALLOWED_HOSTS` and `FORWARDED_ALLOW_IPS`, disable response buffering and allow time for scans. On ECS with an HTTPS ALB listener and HTTP targets, put the public hostname in `ALLOWED_HOSTS` and the ALB subnet CIDRs in `FORWARDED_ALLOW_IPS` (comma-separated). This lets Uvicorn use the forwarded HTTPS scheme for the browser origin check. If an upstream proxy changes the host or scheme, set `PUBLIC_ORIGIN` to the exact external origin, including any non-default port. Limit inbound task traffic to the ALB security group and deploy the new task revision.

Build the image using the README and create a private `.env`. To restrict WhatsApp access, set `WHATSAPP_TESTERS` to a comma-separated list. An empty list accepts direct messages from any number.

```sh
docker run -d --name isitascam --env-file .env -e WHATSAPP_BRIDGE=1 \
  -p 127.0.0.1:8000:8000 -v isitascam-session:/session isitascam
docker logs isitascam
docker exec isitascam cat /tmp/pairing-qr
```

Once the logs say pairing is ready, scan the QR code from **Linked devices** on the phone. Use one bridge per session volume. Keep the volume private and writable by UID 1000. It stores pairing credentials and recent delivery receipts.
