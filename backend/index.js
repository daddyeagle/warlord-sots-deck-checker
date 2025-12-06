// Express server for Discord OAuth2 login
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const axios = require('axios'); // Use one axios import
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// FIX 1: Trust ALL proxies (for Railway)
app.set('trust proxy', true);

// Debug Middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
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

// --- AUTHENTICATION ROUTES ---
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://warlord-sots-deck-checker-production.up.railway.app/api/auth/discord/callback';

app.get('/api/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'identify'
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

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
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

    const accessToken = tokenRes.data.access_token;
    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    req.session.regenerate(function(err) {
      if (err) return res.status(500).send("Session error");
      req.session.user = {
        id: userRes.data.id,
        username: userRes.data.username,
        discriminator: userRes.data.discriminator,
        displayName: userRes.data.global_name || userRes.data.display_name || null
      };
      req.session.save((err) => {
        if (err) return res.status(500).send("Session save failed");
        res.redirect(process.env.FRONTEND_ORIGIN ? `${process.env.FRONTEND_ORIGIN}/auth-success` : '/auth-success');
      });
    });
  } catch (err) {
    console.error('OAuth Error:', err.message);
    res.status(500).send('OAuth2 Error');
  }
});

app.get('/api/auth/success', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  if (!req.session.user) return res.status(401).send('Not authenticated');
  res.json(req.session.user);
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.sendStatus(200));
});

// --- GITHUB HELPER FUNCTIONS (Internal) ---
// These handle the complexity of reading/writing so the route is clean

const GITHUB_OWNER = 'daddyeagle';
const GITHUB_REPO = 'warlord-sots-deck-checker';
const GITHUB_BRANCH = 'deploy-docs';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

async function getGithubFile(path) {
  try {
    const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}?ref=${GITHUB_BRANCH}`;
    const response = await axios.get(url, {
      headers: { 
        'Authorization': `token ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    // Decode Content
    const content = Buffer.from(response.data.content, 'base64').toString('utf8');
    return { sha: response.data.sha, content: content };
  } catch (err) {
    if (err.response && err.response.status === 404) return null; // File doesn't exist yet
    throw err; // Real error
  }
}

async function putGithubFile(path, content, message, sha = null) {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`;
  const body = {
    message: message,
    content: Buffer.from(JSON.stringify(content, null, 2)).toString('base64'),
    branch: GITHUB_BRANCH
  };
  if (sha) body.sha = sha;
  
  await axios.put(url, body, {
    headers: { 
      'Authorization': `token ${GITHUB_TOKEN}`,
      'Accept': 'application/vnd.github.v3+json'
    }
  });
}

// --- DECK SUBMISSION ROUTE ---

app.post('/api/submit-deck', async (req, res) => {
  // 1. Auth Check
  if (!req.session.user) return res.status(401).json({ success: false, error: 'Not authenticated' });
  
  // 2. Destructure inputs (FIXED ORDER)
  const { eventName, warlord, cardList, deckContents } = req.body;
  
  // 3. Validation
  if (!eventName || !warlord || !cardList) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }

  // 4. Prepare User Data
  const username = req.session.user.id;
  const discordUsername = `${req.session.user.username}#${req.session.user.discriminator}`;
  const displayName = req.session.user.displayName || req.session.user.username;
  const timestamp = new Date().toISOString();

  // 5. Define Paths
  // Note: Using 'docs/events' based on previous conversation, change to 'backend/public/events' if you prefer
  const safeEventName = eventName.replace(/[^a-z0-9\-]+/gi, '-').toLowerCase();
  const eventPath = `backend/public/events/${safeEventName}.json`;
  const decksPath = `backend/public/events/decks-${safeEventName}.json`;

  try {
    // --- STEP A: Update Event File (The List of Submissions) ---
    const existingEvent = await getGithubFile(eventPath);
    
    let eventObj = { eventName, submissions: [] };
    let eventSha = null;

    if (existingEvent) {
      eventSha = existingEvent.sha;
      try { eventObj = JSON.parse(existingEvent.content); } catch (e) { console.log("Parse error, resetting"); }
    }

    if (!Array.isArray(eventObj.submissions)) eventObj.submissions = [];

    // CRITICAL LOGIC: Filter out OLD submission by this user, then push NEW one
    eventObj.submissions = eventObj.submissions.filter(sub => sub.username !== username);
    
    eventObj.submissions.push({
      warlord,
      username, // Discord ID
      discord_username: discordUsername,
      display_name: displayName,
      timestamp,
      // Optional: Link to specific file if you are generating one, otherwise this is enough
    });

    await putGithubFile(eventPath, eventObj, `Update event ${eventName} by ${discordUsername}`, eventSha);

    // --- STEP B: Update Decks File (The Detailed Deck Lists) ---
    const existingDecks = await getGithubFile(decksPath);
    
    let decksArr = [];
    let decksSha = null;

    if (existingDecks) {
      decksSha = existingDecks.sha;
      try { decksArr = JSON.parse(existingDecks.content); } catch (e) { console.log("Parse error, resetting"); }
    }

    if (!Array.isArray(decksArr)) decksArr = [];

    // CRITICAL LOGIC: Filter out OLD deck by this user
    decksArr = decksArr.filter(d => d.username !== username);

    // Append NEW deck
    decksArr.push({
      username,
      event: eventName,
      warlord,
      display_name: displayName,
      timestamp,
      cardList: formatCardList(cardList) // Use helper to format cleanly
    });

    await putGithubFile(decksPath, decksArr, `Update deck ${eventName} by ${discordUsername}`, decksSha);

    res.json({ success: true });

  } catch (err) {
    console.error('Submission Error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to save to GitHub', details: err.message });
  }
});

// Helper to format cardList structure
function formatCardList(cardList) {
  const formatted = {};
  for (const type in cardList) {
    const cards = cardList[type];
    let typeCount = 0;
    const combinedCards = {};
    // Add all main deck cards
    for (const card in cards) {
      if (card === 'StartingArmy') continue;
      combinedCards[card] = (combinedCards[card] || 0) + cards[card];
    }
    // Add all Starting Army cards
    if (cards['StartingArmy']) {
      for (const saCard in cards['StartingArmy']) {
        combinedCards[saCard] = (combinedCards[saCard] || 0) + cards['StartingArmy'][saCard];
      }
    }
    // Count total for this type
    for (const card in combinedCards) {
      typeCount += combinedCards[card];
    }
    formatted[type] = { count: typeCount, cards: combinedCards };
    if (cards['StartingArmy']) {
      formatted[type].StartingArmy = { cards: cards['StartingArmy'] };
    }
  }
  return formatted;
}

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