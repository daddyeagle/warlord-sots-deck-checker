# Warlord SOTS Backend (Node.js/Express)

This backend provides Discord OAuth2 login for secure user authentication.

## Features
- Discord OAuth2 login (no PAT required)
- Session management
- Endpoints for login, callback, user info, and logout

## Setup

1. Copy `.env.example` to `.env` and fill in your Discord app credentials:
   - `DISCORD_CLIENT_ID`
   - `DISCORD_CLIENT_SECRET`
   - `DISCORD_REDIRECT_URI` (default: `http://localhost:3001/api/auth/discord/callback`)
   - `SESSION_SECRET`

2. Install dependencies:
   ```bash
   cd backend
   npm install
   ```

3. Start the backend server:
   ```bash
   npm start
   ```

4. Visit `http://localhost:3001/api/auth/discord` to begin Discord login.

## Endpoints
- `GET /api/auth/discord` — Redirects to Discord login
- `GET /api/auth/discord/callback` — Handles Discord OAuth2 callback
- `GET /api/auth/success` — Returns authenticated user info (if logged in)
- `POST /api/auth/logout` — Logs out the user

## Security
- Never commit your real `.env` file or Discord secrets to version control.
- This backend should be run on a secure server for production use.

---

For integration with your frontend, call `/api/auth/discord` to start login and `/api/auth/success` to get the logged-in user.
