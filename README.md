# Is It a Scam?

A vibed self-hosted checker for suspicious messages and links, built in under a week as an experiment to see if AI can help humans detect malicious messages. It explains warning signs and offers recovery steps if someone has already clicked or paid. Use it on the web or through WhatsApp. Contributions and breakages welcome.

## Run locally

From the repository root:

```sh
docker build -t isitascam .
docker run --rm -p 127.0.0.1:8000:8000 -e WHATSAPP_BRIDGE=0 isitascam
```

Open <http://localhost:8000> and choose **Try an example → Message**. Local wording checks work without keys. For AI review or optional link checks, copy `.env.example` to `.env`, fill in the services you want, and add `--env-file .env` before the image name. Providers may charge for use. [Configuration](.env.example)

## Development

Use Python 3.13 and Node.js 22. Run from the repository root:

```sh
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests
npm ci --prefix whatsapp
node --test tests/messages.test.mjs
```

Start the web app with `uvicorn app:app --reload`. For WhatsApp pairing, deployment and data sharing, see the [architecture guide](ARCHITECTURE.md).

## License

[MIT](LICENSE) for the code. [SIL Open Font License](static/fonts/OFL.txt) for DM Sans.
