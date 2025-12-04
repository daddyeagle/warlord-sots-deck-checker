// Express server for Discord OAuth2 login
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const cors = require('cors');

const path = require('path');
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 8080;


// CORS setup: allow requests from frontend (adjust origin as needed)
// CORS setup: allow requests from frontend (adjust origin as needed)
app.use(cors({
  origin: 'https://warlord-sots-deck-checker-production.up.railway.app',
  credentials: true
}));


app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // Always true for Railway/production
    httpOnly: true,
    sameSite: 'none', // Always 'none' for cross-site cookies
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
  }
}));

// Serve static files from /public
app.use(express.static(path.join(__dirname, 'public')));

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'http://localhost:3001/api/auth/discord/callback';

// Step 1: Redirect to Discord OAuth2
app.get('/api/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'identify'
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

// Step 2: Handle Discord OAuth2 callback
app.get('/api/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('No code provided');
  try {
    // Exchange code for access token
    const tokenRes = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      scope: 'identify'
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    const accessToken = tokenRes.data.access_token;
    // Get user info
    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    // Store only user info in session, NOT the access token
    req.session.user = {
      id: userRes.data.id,
      username: userRes.data.username,
      discriminator: userRes.data.discriminator
    };
    res.redirect(process.env.FRONTEND_ORIGIN ? `${process.env.FRONTEND_ORIGIN}/auth-success` : '/api/auth/success');
  } catch (err) {
    res.status(500).send('OAuth2 Error: ' + err.message);
  }
});

// Step 3: Auth success endpoint
app.get('/api/auth/success', (req, res) => {
  if (!req.session.user) return res.status(401).send('Not authenticated');
  res.json({
    id: req.session.user.id,
    username: req.session.user.username,
    discriminator: req.session.user.discriminator
  });
});

// Step 4: Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.sendStatus(200);
  });
});


// SPA fallback: serve index.html for any unknown route (after API routes)
app.get('*', (req, res) => {
  // Only handle non-API requests
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).send('Not found');
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend listening on port ${PORT}`);
});
