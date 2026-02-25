# AuditAgent ⬡

> AI-powered smart contract security auditor for the Base blockchain.

AuditAgent scans any verified Solidity contract on Base for vulnerabilities using Anthropic Claude, then scores every finding using a majority-vote algorithm.

## How it works

1. User pastes a Base contract address + their Anthropic API key
2. Backend fetches verified source code from Basescan
3. Claude scans the contract and returns a list of findings
4. The scoring engine cross-validates findings using majority voting (3 iterations per batch)
5. Results are displayed in a visual dashboard with severity breakdown, match stats, and exportable report

## Stack

- **Frontend** — Single-file HTML/CSS/JS, deployed on Vercel
- **Backend** — FastAPI + Python, deployed on Railway
- **AI Engine** — Anthropic Claude (`claude-sonnet-4-6`)
- **Chain** — Base (via Basescan API)

## Deploy

See [DEPLOY.md](./DEPLOY.md) for full step-by-step instructions.

Quick summary:
1. Push repo to GitHub
2. Deploy `api/` folder to Railway → get URL
3. Set `API_BASE` in `frontend/index.html` to your Railway URL
4. Deploy to Vercel → connect your domain

## Local development

```bash
cd api
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## License

Apache-2.0
