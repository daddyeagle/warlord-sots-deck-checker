# GitHub Token Setup for Config Sync

To enable automatic updates of `warlord_configuration.json` to GitHub from admin.html, follow these steps:

## 1. Create a GitHub Personal Access Token (PAT)
- Go to https://github.com/settings/tokens
- Click "Generate new token"
- Select the `repo` scope (for private repos, or just `public_repo` for public)
- Copy the token (you won't see it again)

## 2. Add the Token to Railway
- In your Railway project dashboard, go to the environment variables/settings.
- Add a new variable:
  - Key: `GITHUB_TOKEN`
  - Value: (paste your token)

## 3. Redeploy Your Service
- Redeploy your Railway service so the new environment variable is available.

## 4. Security Notes
- Never share your token publicly.
- The backend only needs the token for the GitHub API commit/push.
- If you rotate or delete the token, update the Railway variable.

## 5. Troubleshooting
- If GitHub updates fail, check the Railway logs for errors.
- Ensure the token has not expired and has the correct permissions.

---

For questions or issues, see the backend/github.js file for implementation details.
