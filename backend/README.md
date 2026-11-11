# Warlord SOTS Backend (Node.js/Express)

This backend provides Discord OAuth2 login for secure user authentication.

## Features
- Discord OAuth2 login (no PAT required)
- Session management
- Endpoints for login, callback, user info, and logout

## Event deck submissions

In the Config Editor, select **Keep all deck submissions** when creating an
event, or toggle **Keep all decks from each player** under Manage Events. With
the option enabled, each upload adds a separate deck and submission for that
player. By default, a new upload replaces all of that player's previous decks
and submissions for the event. Turning the option off does not immediately
remove decks, but the player's next upload will replace their existing entries.
Withdrawing from an event removes all of that player's decks and submissions.
When a submission includes a required event text field, the downloaded deck CSV
shows its label and value alongside that deck's player information.

## Setup

1. Copy `.env.example` to `.env` and fill in your Discord app credentials:
   - `DISCORD_CLIENT_ID`
   - `DISCORD_CLIENT_SECRET`
   - `DISCORD_REDIRECT_URI` (for Railway: `https://warlord-sots-deck-checker-production.up.railway.app/api/auth/discord/callback`)
   - `SESSION_SECRET`
   - `FRONTEND_ORIGIN` (for Railway: `https://warlord-sots-deck-checker-production.up.railway.app`)

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
