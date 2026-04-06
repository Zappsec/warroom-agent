# Integrations Setup Guide

Step-by-step instructions for setting up all external services and API credentials required by WarRoom Agent.

---

## Table of Contents

1. [Auth0 — Core Identity (Authentication & API)](#1-auth0--core-authentication)
2. [Auth0 — Token Vault/Connected Accounts](#2-auth0--tokenvault-connectedaccounts)
3. [Auth0 — CIBA (Backchannel Authentication)](#3-auth0--ciba-backchannel-authentication)
4. [Auth0 — FGA (Fine-Grained Authorization)](#4-auth0--fga-fine-grained-authorization)
5. [Anthropic Claude (AI/LLM)](#5-anthropic-claude-aillm)
6. [Slack](#6-slack)
7. [Zoom](#7-zoom)
8. [Google Calendar](#8-google-calendar)
9. [Email (SMTP / Gmail)](#9-email-smtp--gmail)
10. [GitHub Remediation Repos](#10-github-remediation-repos)

---

## 1. Auth0 — Core Identity (Authentication & API)

WarRoom uses three Auth0 applications: a **SPA** (frontend), an **M2M** (backend), and a **CIBA** app (backchannel auth).

### Create the Auth0 Tenant

1. Sign up at [auth0.com](https://auth0.com) and create a new tenant
2. Note your **Auth0 Domain** (e.g., `dev-xxxxx.us.auth0.com`)

### Create the API

1. Go to **Applications > APIs > Create API**
2. Name: `WarRoom API`
3. Identifier: `https://warroom-api`
4. Signing Algorithm: RS256
5. Under **Permissions**, add these scopes:
   - `read:incidents`
   - `read:audit`
   - `read:integrations`
   - `approve:actions`
   - `execute:actions`
   - `execute:remediation`
   - `admin:config`

### Create the SPA Application (Frontend)

1. Go to **Applications > Create Application**
2. Name: `WarRoom Agent Console`
3. Type: **Single Page Application**
4. Under **Settings**:
   - Note the **Client ID** --> this is your `VITE_AUTH0_CLIENT_ID`
   - Allowed Callback URLs: `http://localhost:5173, http://localhost:5173/integrations, https://<EC2_IP>, https://<EC2_IP>/integrations`
   - Allowed Logout URLs: `http://localhost:5173, https://<EC2_IP>`
   - Allowed Web Origins: `http://localhost:5173, https://<EC2_IP>`
5. Under **Advanced Settings > Grant Types**, enable:
   - Authorization Code
   - Refresh Token

### Create the M2M Application (Backend)

1. Go to **Applications > Create Application**
2. Name: `WarRoom Agent Backend`
3. Type: **Machine to Machine**
4. Authorize it for the `WarRoom API`
5. Select all scopes
6. Note the **Client ID** and **Client Secret** --> these are your `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET`

### Create the Custom API Client (Token Vault)

1. Go to ** WarRoom API > Add Application**
2. Name: `WarRoom API Token Vault Client`
3. Under Advanced Settings, Select the Token Vault Grant type. 
4. Note the credentials --> `AUTH0_CUSTOM_API_CLIENT_ID` and `AUTH0_CUSTOM_API_CLIENT_SECRET`
5. Set `AUTH0_TOKEN_ENDPOINT` to `https://<your-domain>.us.auth0.com/oauth/token`

### Create the Regular Web Application (CIBA)

1. Go to **Applications > Create Application**
2. Name: `WarRoom Agent Broker`
3. Type: **Regular Web Application**
4. Authorize it for the `WarRoom API` for User Access
5. Select all scopes

### Configure Social Connections

1. Go to **Authentication > Social**
2. Enable the connections needed:
   - **GitHub** — create a Github App at [github.com/settings/developers](https://github.com/settings/developers)
   - **Google** — use Google OAuth2 credentials from Google Cloud Console
   - **Slack** — create a Slack app at [api.slack.com/apps](https://api.slack.com/apps)
3. Note the connection names (defaults: `github`, `google-oauth2`, `sign-in-with-slack`)

### Create Users

1. Go to **User Management > Users > Create User > Create via UI**
2. Create at least two users:
   - **App Operator** — the person who who receives CIBA push notifications for sensitive app remediation actions
   - **Network Operator** — the person who receives CIBA push notifications for sensitive network remediation actions
3. Note each user's **user_id** (e.g., `auth0|69d2159ed457a645174c3a47`)
4. These become `AUTH0_APP_REMEDIATION_OWNER_SUB` and `AUTH0_NETWORK_REMEDIATION_OWNER_SUB`

### Create Roles

1. Go to **User Management > Roles > Create Role**
2. Create at least two roles:
   - **WarRoom Operator** — Role for WarRoom Console users to access the console
   - **remediation_executor** — Role for executing sensitive github remediation actions
3. Assign both roles to App Operator and Network Operator user profiles


### Env vars produced

```env
# Frontend
VITE_AUTH0_DOMAIN=dev-xxxxx.us.auth0.com
VITE_AUTH0_CLIENT_ID=<spa-client-id>
VITE_AUTH0_AUDIENCE=https://warroom-api

# Backend
AUTH0_DOMAIN=dev-xxxxx.us.auth0.com
AUTH0_CLIENT_ID=<m2m-client-id>
AUTH0_CLIENT_SECRET=<m2m-client-secret>
AUTH0_AUDIENCE=https://warroom-api
AUTH0_CUSTOM_API_CLIENT_ID=<token-vault-client-id>
AUTH0_CUSTOM_API_CLIENT_SECRET=<token-vault-client-secret>
AUTH0_TOKEN_ENDPOINT=https://dev-xxxxx.us.auth0.com/oauth/token
AUTH0_SLACK_CONNECTION_NAME=sign-in-with-slack
AUTH0_GOOGLE_CONNECTION_NAME=google-oauth2
AUTH0_GITHUB_CONNECTION_NAME=github
```

---

## 2. Auth0 — CIBA (Backchannel Authentication)

CIBA enables out-of-band approval for sensitive remediation actions. The remediation owner receives a push notification and can approve/deny without being logged into the app.

### Enable CIBA on Your Tenant

1. Contact Auth0 support or check if CIBA is available on your plan
2. CIBA must be enabled at the tenant level before creating a CIBA application

### Create the CIBA Application

1. Go to **Applications > Create Application**
2. Name: `WarRoom CIBA`
3. Type: **Regular Web Application** (CIBA uses confidential clients)
4. Under **Settings**:
   - Note the **Client ID** and **Client Secret**
   - These become `AUTH0_CIBA_CLIENT_ID` and `AUTH0_CIBA_CLIENT_SECRET`
5. Under **Advanced Settings > Grant Types**, enable:
   - **Client Initiated Backchannel Authentication (CIBA)**
6. Under **Advanced Settings > Endpoints**, confirm the backchannel authorize endpoint is available:
   - `https://<your-domain>.us.auth0.com/bc-authorize`

### Configure CIBA Settings

1. Under the CIBA application settings, configure:
   - **Token Delivery Mode**: `poll` (WarRoom polls for the token)
   - **Default Requested Expiry**: `300` seconds (5 minutes)
   - **Default Poll Interval**: `5` seconds

### How It Works

- Backend calls `/bc-authorize` with a `login_hint` (the remediation owner's Auth0 sub) and a `binding_message` (human-readable context)
- Auth0 sends a notification to the remediation owner (via Auth0 Guardian push, email, or SMS depending on your MFA configuration)
- The owner approves or denies
- Backend polls the token endpoint until it receives a token, denial, or expiry

### Env vars produced

```env
AUTH0_CIBA_ENABLED=true
AUTH0_CIBA_CLIENT_ID=<ciba-client-id>
AUTH0_CIBA_CLIENT_SECRET=<ciba-client-secret>
AUTH0_CIBA_AUDIENCE=https://warroom-api
AUTH0_CIBA_SCOPE=openid execute:remediation
AUTH0_CIBA_REQUESTED_EXPIRY=300
AUTH0_CIBA_DEFAULT_POLL_INTERVAL=5
AUTH0_APP_REMEDIATION_OWNER_SUB=auth0|<app-remediation-owner-user-id>
AUTH0_NETWORK_REMEDIATION_OWNER_SUB=auth0|<network-remediation-owner-user-id>
```

---

## 3. Auth0 — FGA (Fine-Grained Authorization)

Auth0 FGA provides relationship-based access control. WarRoom uses it to check if a user `can_approve` or `can_execute` actions on an incident.

### Set Up FGA

1. Go to [dashboard.fga.dev](https://dashboard.fga.dev) and create an account
2. Create a new **Store**
3. Note the **Store ID** --> `FGA_STORE_ID`

### Create an Authorization Model

1. In your FGA store, create a new authorization model
2. Define types and relations for your access control (e.g., `incident` type with `can_approve` and `can_execute` relations)
3. Note the **Model ID** --> `FGA_MODEL_ID`

### Create FGA API Credentials

1. Go to **Settings > API Credentials** in the FGA dashboard
2. Create a new client
3. Note the **Client ID** and **Client Secret**

### Write Tuples

Write relationship tuples to define who can do what:

```
user:auth0|<user-id> can_approve incident:<incident-id>
user:auth0|<user-id> can_execute incident:<incident-id>
```

### Env vars produced

```env
FGA_API_URL=https://api.us1.fga.dev
FGA_STORE_ID=<store-id>
FGA_MODEL_ID=<model-id>
FGA_CLIENT_ID=<fga-client-id>
FGA_CLIENT_SECRET=<fga-client-secret>
FGA_API_TOKEN_ISSUER=https://auth.fga.dev
FGA_API_AUDIENCE=https://api.us1.fga.dev/
```

---

## 4. Anthropic Claude (AI/LLM)

Used for incident classification, action planning, and the AI chat assistant.

### Get an API Key

1. Sign up at [console.anthropic.com](https://console.anthropic.com)
2. Go to **API Keys > Create Key**
3. Copy the key (starts with `sk-ant-...`)

### Env vars produced

```env
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-5
```

---

## 5. Slack

Used for incident detection (polling channels) and responder notifications (DMs).

### Create a Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps) > **Create New App**
2. Choose **From scratch**
3. Name: `WarRoom Agent`, select your workspace

### Configure Bot Permissions

1. Go to **OAuth & Permissions**
2. Under **Bot Token Scopes**, add:
   - `channels:history` — read channel messages
   - `channels:read` — list channels
   - `chat:write` — send messages
   - `im:write` — send DMs
   - `users:read` — lookup user info
   - `users:read.email` — lookup users by email

### Install to Workspace

1. Go to **Install App** > **Install to Workspace**
2. Authorize the permissions
3. Copy the **Bot User OAuth Token** (starts with `xoxb-`)

### Get the Signing Secret

1. Go to **Basic Information**
2. Copy the **Signing Secret**

### Get the Channel ID

1. In Slack, right-click the channel you want to monitor > **View channel details**
2. At the bottom, copy the **Channel ID** (e.g., `C0AQVTDQU7J`)
3. Make sure the bot is invited to this channel

### Env vars produced

```env
SLACK_BOT_TOKEN=xoxb-...
SLACK_SIGNING_SECRET=<signing-secret>
SLACK_CHANNEL_ID=<channel-id>
SLACK_POLL_INTERVAL=10
```

---

## 6. Zoom

Used to automatically create war room meetings for incident coordination.

### Create a Server-to-Server OAuth App

1. Go to [marketplace.zoom.us](https://marketplace.zoom.us) > **Develop > Build App**
2. Choose **Server-to-Server OAuth**
3. Name: `WarRoom Agent`

### Configure Scopes

1. Under **Scopes**, add:
   - `meeting:write:admin` — create meetings
   - `meeting:read:admin` — read meeting details
   - `user:read:admin` — lookup users

### Activate the App

1. Complete all required fields
2. Activate the app
3. Note the **Client ID**, **Client Secret**, and **Account ID**

### Env vars produced

```env
ZOOM_CLIENT_ID=<client-id>
ZOOM_CLIENT_SECRET=<client-secret>
ZOOM_ACCOUNT_ID=<account-id>
```

---

## 7. Google Calendar

Used to create bridge call calendar events with responders as attendees.

### Create a Google Cloud Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Enable the **Google Calendar API** (APIs & Services > Library > search "Google Calendar API" > Enable)

### Create a Service Account

1. Go to **IAM & Admin > Service Accounts > Create Service Account**
2. Name: `warroom-calendar`
3. Skip the optional role/access steps
4. Click on the created service account > **Keys > Add Key > Create New Key**
5. Choose **JSON** and download the key file

### Enable Domain-Wide Delegation (Google Workspace only)

If using Google Workspace:

1. Go to the service account details > **Enable domain-wide delegation**
2. In Google Workspace Admin Console (admin.google.com):
   - Go to **Security > API controls > Domain-wide delegation**
   - Add a new client with the service account's Client ID
   - Scopes: `https://www.googleapis.com/auth/calendar`

### For Personal Gmail Accounts

Domain-wide delegation is not available. The service account can only manage its own calendar. You may need to share calendars explicitly.

### Place the Key File

Copy the downloaded JSON key file to a secure location on your server (e.g., `/home/ec2-user/warroom/backend/google-service-account.json`).

### Env vars produced

```env
GOOGLE_SERVICE_ACCOUNT_KEY=/path/to/google-service-account.json
```

---

## 8. Email (SMTP / Gmail)

Used to send escalation emails to stakeholders.

### Using Gmail

1. Enable **2-Step Verification** on your Google account at [myaccount.google.com/security](https://myaccount.google.com/security)
2. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Select **Mail** and your device
4. Generate and copy the **App Password** (16-character code)

### Using Other SMTP Providers

Any SMTP server works. Update `SMTP_HOST` and `SMTP_PORT` accordingly (e.g., SendGrid, Mailgun, AWS SES).

### Env vars produced

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=<16-char-app-password>
```

---

## 9. GitHub Remediation Repos

WarRoom commits config changes to GitHub repos as part of remediation. Two repos are used: one for application service config, one for network policies.

### Create the Repositories

1. Create two repositories in your GitHub org:
   - **App Remediation** (e.g., `your-org/warroom-app-remediation`)
     - Add a `service-config.json` file with your app's service configuration
   - **Network Remediation** (e.g., `your-org/warroom-network-remediation`)
     - Add a `network-policy.json` file with your network policy configuration

### Create a Personal Access Token

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Generate a **Fine-grained token** or **Classic token** with:
   - `repo` scope (full control of repositories)
3. Copy the token
4. The backend uses this token via environment or the Auth0 Token Vault integration

### Env vars produced

```env
GITHUB_APP_REMEDIATION_REPO=your-org/warroom-app-remediation
GITHUB_APP_REMEDIATION_PATH=service-config.json
GITHUB_NETWORK_REMEDIATION_REPO=your-org/warroom-network-remediation
GITHUB_NETWORK_REMEDIATION_PATH=network-policy.json
```

---

## Quick Checklist

Use this checklist to verify all integrations are configured:

- [ ] Auth0 tenant created with SPA, M2M, and CIBA applications
- [ ] Auth0 API created with all required scopes
- [ ] Auth0 SPA callback/logout/origin URLs configured
- [ ] Auth0 social connections enabled (GitHub, Google, Slack)
- [ ] Auth0 CIBA enabled and configured with poll mode
- [ ] Auth0 FGA store and authorization model created
- [ ] Auth0 users created (operator + remediation owners)
- [ ] Anthropic API key generated
- [ ] Slack app created with bot permissions and installed to workspace
- [ ] Slack bot invited to the incident channel
- [ ] Zoom Server-to-Server OAuth app created and activated
- [ ] Google Calendar API enabled with service account key
- [ ] Gmail App Password generated (or alternative SMTP configured)
- [ ] GitHub remediation repos created with config files
- [ ] GitHub Personal Access Token generated
- [ ] All environment variables populated in `backend/.env` and root `.env`
