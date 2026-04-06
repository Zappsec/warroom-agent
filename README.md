# WarRoom Agent

AI-powered security incident war room that orchestrates detection, triage, coordination, and remediation — with Auth0 CIBA (Client Initiated Backchannel Authentication) for human-in-the-loop approval of sensitive actions.

Built for the **Auth0 Hackathon**.

---

## What It Does

WarRoom Agent monitors Slack channels for security incidents, uses Claude AI to classify severity and plan response actions, coordinates teams via Slack/Zoom/Calendar/Email, and executes remediation — requiring out-of-band human approval (via Auth0 CIBA) before touching sensitive systems like GitHub repos.

### Key Features

- **AI Incident Classification** — Claude LLM analyzes raw incident text to determine severity (P1/P2/P3), affected domains, impacted systems, and confidence scores
- **Automatic Responder Resolution** — Matches on-call responders based on incident domain, expertise, and availability
- **Known Issue Matching** — Searches historical knowledge base for similar past incidents and suggests remediation steps
- **AI Action Planning** — Generates coordination actions: Zoom war rooms, calendar bridges, Slack DMs, email escalations, and GitHub config remediation
- **Auth0 CIBA Approval Flow** — Sensitive GitHub remediation actions trigger backchannel push notifications to the remediation owner for out-of-band approval before execution
- **Auth0 FGA (Fine-Grained Authorization)** — Role-based access checks for approving and executing actions
- **Interactive AI Chat** — Incident-scoped chat assistant for runbooks, diagnostics, and root cause analysis
- **Full Audit Trail** — Every AI decision, human approval, and action execution is logged
- **Demo Console** — Inject test incidents to walk through the full workflow

### CIBA Flow

```
Operator approves sensitive action
    --> Backend initiates Auth0 CIBA backchannel request
    --> Auth0 sends push notification to remediation owner
    --> Owner approves out-of-band (phone/email)
    --> Backend receives token, validates scopes
    --> Action executes with approved owner's context
    --> Full audit trail recorded
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, TypeScript, Vite, TailwindCSS, Radix UI (shadcn) |
| **Backend** | FastAPI (Python), SQLAlchemy, SQLite |
| **AI/LLM** | Anthropic Claude (claude-sonnet-4-5), LangGraph workflow orchestration |
| **Auth** | Auth0 (OAuth2/OIDC), Auth0 CIBA, Auth0 FGA |
| **Integrations** | Slack, Zoom, Google Calendar, Gmail SMTP, GitHub |
| **Deployment** | GitHub Actions CI/CD, AWS EC2, Nginx, systemd |

---

## Prerequisites

- [**Node.js** 20+](https://nodejs.org/en/download/)
- [**Python** 3.12+](https://www.python.org/downloads/)
- [**npm** 9+](https://nodejs.org/en/download/)
- [**Git**](https://git-scm.com/install/)

External accounts required (see [integrations-setup.md](integrations-setup.md) for detailed setup guides):

- Auth0 tenant (with CIBA and FGA configured)
- Anthropic API key
- Slack workspace + bot app
- Zoom Server-to-Server OAuth app
- Google Cloud service account (Calendar API)
- Gmail App Password (or other SMTP provider)
- GitHub Personal Access Token

---

## Local Development Setup

### 1. Clone the repository

```bash
git clone git@github.com:Zappsec/warroom-agent.git
cd warroom-agent
```

### 2. Frontend setup

```bash
npm install
```

Create a `.env.local` file in the project root (this file is gitignored and used by Vite for local development):

```bash
cp .env.example .env.local
nano .env.local
```

```env
VITE_AUTH0_DOMAIN=dev-xxxxxxxxxxxx.us.auth0.com
VITE_AUTH0_CLIENT_ID=<Client Id>
VITE_AUTH0_AUDIENCE=<your adudience name example https://warroom-api>
VITE_AUTH0_SCOPE=openid profile email offline_access read:incidents read:audit read:integrations approve:actions execute:actions admin:config
```

> **Note:** When deploying via the CI/CD pipeline, these are not read from a file. Instead, they are injected as **GitHub Secrets** (see [CI/CD Pipeline](#cicd-pipeline-automatic-deployments) section). Make sure the same values are added as GitHub Secrets: `VITE_AUTH0_DOMAIN`, `VITE_AUTH0_CLIENT_ID`, `VITE_AUTH0_AUDIENCE`.

Start the dev server:

```bash
npm run dev
```

Frontend will be available at `http://localhost:8080`.

### 3. Backend setup

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Create `backend/.env` by copying the example and filling in your secrets:

```bash
cp .env.example .env
nano .env
```

See [integrations-setup.md](integrations-setup.md) for how to obtain each secret. A full list of environment variables is in the [Environment Variables](#environment-variables) section below.

### 4. Seed the database and start the backend

```bash
# Inside backend/ with venv activated
python -m scripts.seed_data
uvicorn app.main:app --reload --port 8000
```

Backend API will be available at `http://localhost:8000`.

### 5. Verify

- Open `http://localhost:8080` — you should see the landing page
- Log in with Auth0
- Navigate to the Demo Console (`/demo`) to inject a test incident
- Watch the AI classify, plan actions, and route through approval

---

## EC2 Deployment

### One-Time Server Setup

1. **Launch an EC2 instance** (Amazon Linux 2023, t3.small or larger)

2. **Configure Security Group** — allow inbound ports: **22** (SSH), **80** (HTTP), **443** (HTTPS)

3. **Update the EC2 IP** in `scripts/ec2-setup-ssl.sh` (line 16) with your instance's public IP

4. **SSH in and run the setup scripts:**

```bash
ssh -i your-key.pem ec2-user@<EC2_PUBLIC_IP>

# Upload scripts first (or clone the repo)
cd ~/warroom/scripts
chmod +x ec2-setup.sh ec2-setup-ssl.sh

# Step 1: Base setup — packages, venv, systemd services
sudo ./ec2-setup.sh

# Step 2: SSL + Nginx reverse proxy (required for Auth0 SPA SDK)
sudo ./ec2-setup-ssl.sh
```

5. **Fill in `.env` files** on the server:

```bash
nano ~/warroom/backend/.env
nano ~/warroom/.env
```

6. **Seed the database:**

```bash
cd ~/warroom/backend
source venv/bin/activate
python -m scripts.seed_data
```

7. **Start services:**

```bash
sudo systemctl start warroom-backend
sudo systemctl restart nginx
```

8. **Update Auth0 Dashboard** with your EC2 URLs:
   - Allowed Callback URLs: `https://<EC2_PUBLIC_IP>/integrations`
   - Allowed Logout URLs: `https://<EC2_PUBLIC_IP>`
   - Allowed Web Origins: `https://<EC2_PUBLIC_IP>`

### CI/CD Pipeline (Automatic Deployments)

Every push to `main` triggers the GitHub Actions pipeline (`.github/workflows/deploy.yml`) which automatically:

1. Builds the frontend with Vite (Auth0 env vars injected from GitHub Secrets)
2. Writes `backend/.env` from the `BACKEND_ENV` secret
3. Syncs code + built `dist/` to EC2 via rsync
4. Installs/updates Python dependencies in the venv
5. Restarts `warroom-backend` and `nginx`

**Required GitHub Secrets** (Settings > Secrets and variables > Actions):

| Secret | Description |
|--------|------------|
| `EC2_SSH_PRIVATE_KEY` | Contents of your `.pem` key file |
| `EC2_HOST` | EC2 public IP address |
| `EC2_USER` | `ec2-user` |
| `VITE_AUTH0_DOMAIN` | Auth0 tenant domain (e.g., `dev-xxxxx.us.auth0.com`) |
| `VITE_AUTH0_CLIENT_ID` | Auth0 SPA application client ID |
| `VITE_AUTH0_AUDIENCE` | `https://warroom-api` |
| `VITE_AUTH0_SCOPE` | `openid profile email offline_access read:incidents read:audit read:integrations approve:actions execute:actions admin:config` |
| `BACKEND_ENV` | Full contents of `backend/.env` (all secrets) |

### Useful EC2 Commands

```bash
# Check service status
sudo systemctl status warroom-backend
sudo systemctl status nginx

# Tail backend logs
journalctl -u warroom-backend -f

# Health check
curl -k https://localhost/health

# Restart after config changes
sudo systemctl restart warroom-backend
sudo systemctl restart nginx
```

---

## Environment Variables

### Frontend (`.env.local` for local dev, GitHub Secrets for CI/CD)

| Variable | Description |
|----------|------------|
| `VITE_AUTH0_DOMAIN` | Auth0 tenant domain (e.g., `dev-xxxxx.us.auth0.com`) |
| `VITE_AUTH0_CLIENT_ID` | Auth0 SPA application client ID |
| `VITE_AUTH0_AUDIENCE` | Auth0 API identifier (e.g., `https://warroom-api`) |
| `VITE_AUTH0_SCOPE` | Auth0 scopes: `openid profile email offline_access read:incidents read:audit read:integrations approve:actions execute:actions admin:config` |

### Backend (`backend/.env`)

| Variable | Description |
|----------|------------|
| **Database** | |
| `DATABASE_URL` | Database connection string (default: `sqlite:///./warroom.db`) |
| **App** | |
| `APP_ENV` | `development` or `production` |
| `LOG_LEVEL` | Logging level (default: `INFO`) |
| `JWT_SECRET` | Random secret for JWT signing |
| **Anthropic Claude** | |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `ANTHROPIC_MODEL` | Model name (default: `claude-sonnet-4-5`) |
| **Slack** | |
| `SLACK_BOT_TOKEN` | Slack bot token (`xoxb-...`) |
| `SLACK_SIGNING_SECRET` | Slack webhook signing secret |
| `SLACK_CHANNEL_ID` | Channel ID to poll for incidents |
| `SLACK_POLL_INTERVAL` | Polling interval in seconds (default: `10`) |
| **Zoom** | |
| `ZOOM_CLIENT_ID` | Zoom Server-to-Server OAuth client ID |
| `ZOOM_CLIENT_SECRET` | Zoom Server-to-Server OAuth client secret |
| `ZOOM_ACCOUNT_ID` | Zoom account ID |
| **Google Calendar** | |
| `GOOGLE_SERVICE_ACCOUNT_KEY` | Path to Google service account JSON key file |
| **Email (SMTP)** | |
| `SMTP_HOST` | SMTP server (default: `smtp.gmail.com`) |
| `SMTP_PORT` | SMTP port (default: `587`) |
| `SMTP_USER` | SMTP username/email |
| `SMTP_PASS` | SMTP password or app password |
| **Auth0 Core** | |
| `AUTH0_DOMAIN` | Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Auth0 M2M application client ID |
| `AUTH0_CLIENT_SECRET` | Auth0 M2M application client secret |
| `AUTH0_AUDIENCE` | Auth0 API audience |
| **Auth0 Token Vault** | |
| `AUTH0_CUSTOM_API_CLIENT_ID` | Custom API client ID |
| `AUTH0_CUSTOM_API_CLIENT_SECRET` | Custom API client secret |
| `AUTH0_TOKEN_ENDPOINT` | Auth0 token endpoint URL |
| **Auth0 Connections** | |
| `AUTH0_SLACK_CONNECTION_NAME` | Slack social connection name |
| `AUTH0_GOOGLE_CONNECTION_NAME` | Google social connection name |
| `AUTH0_GITHUB_CONNECTION_NAME` | GitHub social connection name |
| **Auth0 FGA** | |
| `FGA_API_URL` | FGA API URL |
| `FGA_STORE_ID` | FGA store ID |
| `FGA_MODEL_ID` | FGA authorization model ID |
| `FGA_CLIENT_ID` | FGA client ID |
| `FGA_CLIENT_SECRET` | FGA client secret |
| `FGA_API_TOKEN_ISSUER` | FGA token issuer |
| `FGA_API_AUDIENCE` | FGA API audience |
| **Auth0 CIBA** | |
| `AUTH0_CIBA_ENABLED` | Enable/disable CIBA (`true`/`false`) |
| `AUTH0_CIBA_CLIENT_ID` | CIBA application client ID |
| `AUTH0_CIBA_CLIENT_SECRET` | CIBA application client secret |
| `AUTH0_CIBA_AUDIENCE` | CIBA audience |
| `AUTH0_CIBA_SCOPE` | CIBA scopes (default: `openid execute:remediation`) |
| `AUTH0_CIBA_REQUESTED_EXPIRY` | CIBA request expiry in seconds (default: `300`) |
| `AUTH0_CIBA_DEFAULT_POLL_INTERVAL` | Polling interval in seconds (default: `5`) |
| `AUTH0_APP_REMEDIATION_OWNER_SUB` | Auth0 user ID for app remediation owner |
| `AUTH0_NETWORK_REMEDIATION_OWNER_SUB` | Auth0 user ID for network remediation owner |
| **GitHub Remediation** | |
| `GITHUB_APP_REMEDIATION_REPO` | App config remediation repo (`org/repo`) |
| `GITHUB_APP_REMEDIATION_PATH` | File path in app remediation repo |
| `GITHUB_NETWORK_REMEDIATION_REPO` | Network policy remediation repo (`org/repo`) |
| `GITHUB_NETWORK_REMEDIATION_PATH` | File path in network remediation repo |
| **CORS** | |
| `CORS_ORIGINS` | Allowed origins JSON array |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/incidents` | List incidents (filter by severity, status, search) |
| `GET` | `/api/incidents/{id}` | Get incident with full context |
| `POST` | `/api/incidents/inject` | Inject demo incident |
| `GET` | `/api/actions` | List planned actions |
| `POST` | `/api/actions/{id}/approve` | Approve action (FGA-gated) |
| `POST` | `/api/actions/{id}/deny` | Deny action (FGA-gated) |
| `POST` | `/api/actions/{id}/prepare-execute` | Prepare execution (routes to CIBA if sensitive) |
| `POST` | `/api/actions/{id}/ciba/start` | Initiate CIBA backchannel auth |
| `GET` | `/api/actions/{id}/ciba/status` | Poll CIBA approval status |
| `GET` | `/api/audit` | Audit trail (filter by incident, actor, event) |
| `GET` | `/api/integrations` | List integration connections |
| `POST` | `/api/integrations/{id}/reconnect` | Reconnect integration |
| `POST` | `/api/chat` | Incident-scoped AI chat |
| `GET` | `/health` | Health check |

---

## Project Structure

```
warroom-agent/
├── .github/workflows/
│   └── deploy.yml              # CI/CD pipeline
├── backend/
│   ├── app/
│   │   ├── agents/             # LangGraph workflow orchestration
│   │   ├── api/                # FastAPI route handlers
│   │   ├── integrations/       # Slack, Zoom, Calendar, Email, GitHub, Auth0 adapters
│   │   ├── models/             # SQLAlchemy models
│   │   ├── security/           # JWT verification, FGA checks, CIBA enforcement
│   │   ├── services/           # Business logic (classifier, planner, CIBA, etc.)
│   │   └── main.py             # FastAPI app entry point
│   ├── scripts/                # DB seed scripts
│   └── requirements.txt
├── src/                        # React frontend (TypeScript)
│   ├── components/             # UI components (shadcn + custom)
│   ├── pages/                  # Route pages
│   ├── hooks/                  # Custom React hooks
│   └── lib/                    # API client, Auth0 config
├── scripts/
│   ├── ec2-setup.sh            # EC2 base setup
│   └── ec2-setup-ssl.sh        # Nginx + SSL setup
├── package.json
├── vite.config.ts
└── tailwind.config.js
```

---

## License

MIT
