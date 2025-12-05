// --- Admin File Download Endpoint ---
// Streams a file from the events directory for download
// Place this after app is initialized and middleware is set up

// ...existing code...


// Express server for Discord OAuth2 login
require('dotenv').config();

const fs = require('fs');
const fsp = require('fs/promises');
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const { getFile, putFile } = require('./github'); // GitHub helper import

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


// --- Deck Submission API ---
// Use EVENTS_PATH env variable, default to relative path for local dev, absolute for Railway
const EVENTS_PATH = process.env.EVENTS_PATH || (process.env.RAILWAY_STATIC_URL ? '/backend/public/events' : 'backend/public/events');

app.post('/api/submit-deck', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });

  const { eventName, warlord, cardList, deckContents } = req.body;
  if (!eventName || !warlord || !cardList || !deckContents) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const username = req.session.user.id;
  const discordUsername = `${req.session.user.username}#${req.session.user.discriminator}`;
  const displayName = req.session.user.displayName || '';
  const timestamp = new Date().toISOString();

  // Sanitize event name for filename
  const safeEventName = eventName.replace(/[^a-z0-9\-]+/gi, '-').toLowerCase();
  const eventPath = `${EVENTS_PATH}/${safeEventName}.json`;
  const decksPath = `${EVENTS_PATH}/decks-${safeEventName}.json`;

try {
    // Ensure parent directories exist before writing files
    await fsp.mkdir(path.dirname(eventPath), { recursive: true });
    await fsp.mkdir(path.dirname(decksPath), { recursive: true });
    // PART 1: Update Event File (local fs)
    let eventObj = { eventName, submissions: [] };
    try {
      if (fs.existsSync(eventPath)) {
        const raw = await fsp.readFile(eventPath, 'utf8');
        eventObj = JSON.parse(raw);
      }
    } catch (err) {
      console.log(`Event file ${eventPath} not found or error reading, creating new.`);
    }
    if (!Array.isArray(eventObj.submissions)) eventObj.submissions = [];
    eventObj.submissions = eventObj.submissions.filter(sub => sub.username !== username);
    eventObj.submissions.push({
      warlord,
      username,
      discord_username: discordUsername,
      display_name: displayName,
      timestamp
    });
    await fsp.writeFile(eventPath, JSON.stringify(eventObj, null, 2), 'utf8');

    // Debug log for event file
    console.log('[Deck Submission] Wrote event file to:', eventPath);
    console.log('[Deck Submission] Event file contents:', JSON.stringify(eventObj, null, 2));

    // PART 2: Update Decks File (local fs)
    let decksArr = [];
    try {
      if (fs.existsSync(decksPath)) {
        const rawDecks = await fsp.readFile(decksPath, 'utf8');
        decksArr = JSON.parse(rawDecks);
      }
    } catch (err) {
      console.log(`Decks file ${decksPath} not found or error reading, creating new.`);
    }
    if (!Array.isArray(decksArr)) decksArr = [];
    decksArr = decksArr.filter(deck => deck.username !== username);
    decksArr.push({
      username,
      event: eventName,
      warlord,
      display_name: displayName,
      timestamp,
      cardList: formatCardList(cardList)
    });
    await fsp.writeFile(decksPath, JSON.stringify(decksArr, null, 2), 'utf8');

    // Debug log for decks file
    console.log('[Deck Submission] Wrote decks file to:', decksPath);
    console.log('[Deck Submission] Decks file contents:', JSON.stringify(decksArr, null, 2));

    // Helper to format cardList (Internal function)
    function formatCardList(cardList) {
      const formatted = {};
      for (const type in cardList) {
        const cards = cardList[type];
        let typeCount = 0;
        const typeCards = {};
        for (const card in cards) {
          if (card === 'StartingArmy') continue;
          typeCards[card] = cards[card];
          typeCount += cards[card];
        }
        if (cards['StartingArmy']) {
          let saCount = 0;
          for (const saCard in cards['StartingArmy']) {
            saCount += cards['StartingArmy'][saCard];
          }
          typeCount += saCount;
          formatted[type] = { count: typeCount, cards: typeCards, StartingArmy: { cards: cards['StartingArmy'] } };
        } else {
          formatted[type] = { count: typeCount, cards: typeCards };
        }
      }
      return formatted;
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Deck submission error:', err.message);
    res.status(500).json({ error: 'Deck submission failed', details: err.message });
  }
});


// Step 4: Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.sendStatus(200);
  });
});

// SPA fallback
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).send('Not found');
  }
});
// Place this before app.listen(...)
app.get('/api/admin/download', async (req, res) => {
  // TODO: Add authentication/authorization for real admin security
  const file = req.query.file;
  if (!file || !/^[a-zA-Z0-9_.\-]+$/.test(file)) {
    return res.status(400).json({ error: 'Invalid file name' });
  }
  const EVENTS_PATH = process.env.EVENTS_PATH || (process.env.RAILWAY_STATIC_URL ? '/backend/public/events' : 'backend/public/events');
  const filePath = `${EVENTS_PATH}/${file}`;
  try {
    await fsp.access(filePath);
    res.download(filePath, file);
  } catch (err) {
    res.status(404).json({ error: 'File not found' });
  }
});
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend listening on port ${PORT}`);
});