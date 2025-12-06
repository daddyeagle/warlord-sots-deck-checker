// Express server for Discord OAuth2 login
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// FIX 1: Trust ALL proxies (aggressive fix for Railway)
app.set('trust proxy', true);

// Debug Middleware
app.use((req, res, next) => {
  console.log('--- Debug Info ---');
  console.log('Path:', req.path);
  console.log('Protocol:', req.protocol); 
  console.log('Secure:', req.secure);     
  console.log('X-Forwarded-Proto:', req.get('x-forwarded-proto')); 
  next();
});

// CORS setup
app.use(cors({
  origin: 'https://warlord-sots-deck-checker-production.up.railway.app',
  credentials: true
}));

app.use(express.json());

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace_this_secret',
  resave: false,
  // FIX 2: Force save uninitialized to ensure cookie is always attempted
  saveUninitialized: true,
  cookie: {
    secure: true, 
    sameSite: 'lax', 
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://warlord-sots-deck-checker-production.up.railway.app/api/auth/discord/callback';

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
    
    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    // FIX 3: Regenerate session to prevent fixation and force new cookie
    req.session.regenerate(function(err) {
      if (err) {
        console.error("Session regeneration failed:", err);
        return res.status(500).send("Session error");
      }

      // Store user info, including display name if available
      req.session.user = {
        id: userRes.data.id,
        username: userRes.data.username,
        discriminator: userRes.data.discriminator,
        displayName: userRes.data.global_name || userRes.data.display_name || null
      };

      // Force save before redirect
      req.session.save((err) => {
        if (err) {
          console.error("Session save failed:", err);
          return res.status(500).send("Session save failed");
        }
        console.log("Session saved successfully. ID:", req.sessionID);
        console.log("User:", req.session.user.username);
        
        res.redirect(process.env.FRONTEND_ORIGIN ? `${process.env.FRONTEND_ORIGIN}/auth-success` : '/auth-success');
      });
    });

  } catch (err) {
    console.error('OAuth Error:', err.response ? err.response.data : err.message);
    res.status(500).send('OAuth2 Error: ' + err.message);
  }
});

// Step 3: Auth success endpoint
app.get('/api/auth/success', (req, res) => {
  // CRITICAL FIX: Prevent browser from caching the "Not Authenticated" state
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');

  console.log("Checking session for /api/auth/success:", req.session);
  console.log("Session ID:", req.sessionID);
  
  if (!req.session.user) return res.status(401).send('Not authenticated');
  
  res.json({
    id: req.session.user.id,
    username: req.session.user.username,
    discriminator: req.session.user.discriminator,
    displayName: req.session.user.displayName || null
  });
});

// Step 4: Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.sendStatus(200);
  });
});

// Deck submission via GitHub API (GET/PUT method)

// Save deck files to /backend/public/events

// Deck submission via GitHub API (GET/PUT method)


const axiosGithub = require('axios');



app.post('/api/submit-deck', async (req, res) => {
    const deckData = {
      eventName,
      warlord,
      cardList,
      submittedBy: {
        id: req.session.user.id,
        username: req.session.user.username,
        discriminator: req.session.user.discriminator,
        displayName: req.session.user.displayName || null
      },
      submittedAt: new Date().toISOString()
    };
      const { eventName, warlord, cardList } = req.body; // Move destructuring to the top
      // Do not reference eventName, warlord, or cardList before this line!
  if (!req.session.user) {
    return res.status(401).json({ success: false, error: 'Not authenticated' });
  }
  if (!eventName || !warlord || !cardList) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }

  // GitHub repo info
  const owner = 'daddyeagle';
  const repo = 'warlord-sots-deck-checker';
  const branch = 'deploy-docs';
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    return res.status(500).json({ success: false, error: 'GitHub token not configured' });
  }

  // Build filename: eventName-warlord-username-timestamp.json
  const safeEvent = String(eventName).replace(/[^a-zA-Z0-9_-]/g, '_');
  const safeWarlord = String(warlord).replace(/[^a-zA-Z0-9_-]/g, '_');
  const safeUser = String(req.session.user.username).replace(/[^a-zA-Z0-9_-]/g, '_');
  const timestamp = Date.now();
  const filename = `${safeEvent}__${safeWarlord}__${safeUser}__${timestamp}.json`;
  const githubPath = `backend/public/events/${filename}`;

  try {
    // Step 1: GET for SHA (if file exists)
    let sha = undefined;
    try {
      const getUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${githubPath}?ref=${branch}`;
      const getRes = await axiosGithub.get(getUrl, {
        headers: {
          'Authorization': `token ${token}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });
      if (getRes.data && getRes.data.sha) {
        sha = getRes.data.sha;
      }
    } catch (err) {
      // 404 is expected for new files
      if (err.response && err.response.status !== 404) {
        throw err;
      }
    }

    // Step 2: PUT to create/update deck file
    const putUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${githubPath}`;
    const content = Buffer.from(JSON.stringify(deckData, null, 2)).toString('base64');
    const body = {
      message: `Submit deck for ${eventName} (${warlord}) by ${safeUser}`,
      content,
      branch
    };
    if (sha) body.sha = sha;
    const putRes = await axiosGithub.put(putUrl, body, {
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    if (!(putRes.status === 201 || putRes.status === 200)) {
      throw new Error('GitHub PUT failed');
    }

    // Step 3: Update event file in same path (e.g., backend/public/events/<eventName>.json)
    const eventFileName = `${safeEvent}.json`;
    const eventFilePath = `backend/public/events/${eventFileName}`;
    let eventSha = undefined;
    let eventList = [];
    try {
      const eventGetUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${eventFilePath}?ref=${branch}`;
      const eventGetRes = await axiosGithub.get(eventGetUrl, {
        headers: {
          'Authorization': `token ${token}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });
      if (eventGetRes.data && eventGetRes.data.sha) {
        eventSha = eventGetRes.data.sha;
        // Decode and parse the existing event file
        const buff = Buffer.from(eventGetRes.data.content, 'base64');
        eventList = JSON.parse(buff.toString('utf8'));
      }
    } catch (err) {
      // 404 is expected for new files
      if (!(err.response && err.response.status === 404)) {
        throw err;
      }
    }
    // Add new deck metadata to event list
    eventList.push({
      warlord,
      submittedBy: deckData.submittedBy,
      submittedAt: deckData.submittedAt,
      deckFile: filename
    });
    const eventPutUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${eventFilePath}`;
    const eventContent = Buffer.from(JSON.stringify(eventList, null, 2)).toString('base64');
    const eventBody = {
      message: `Update event file for ${eventName} (add deck by ${safeUser})`,
      content: eventContent,
      branch
    };
    if (eventSha) eventBody.sha = eventSha;
    await axiosGithub.put(eventPutUrl, eventBody, {
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    return res.json({ success: true });
  } catch (err) {
    console.error('GitHub deck submit error:', err.response ? err.response.data : err.message);
    return res.status(500).json({ success: false, error: 'Failed to submit deck to GitHub' });
  }
});

// SPA fallback
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).send('Not found');
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend listening on port ${PORT}`);
});