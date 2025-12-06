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
// --- ADMIN DOWNLOAD ENDPOINTS ---
// Download event file
const ExcelJS = require('exceljs');

async function jsonToExcel(json, type) {
  if (!json) return null;
  const workbook = new ExcelJS.Workbook();
  const sheet = workbook.addWorksheet('Sheet1');
  if (type === 'event') {
    // Expect { eventName, submissions: [{ discord_username, display_name, warlord }] }
    const obj = typeof json === 'string' ? JSON.parse(json) : json;
    sheet.addRow(['discord_username', 'display_name', 'warlord']);
    sheet.getRow(1).font = { bold: true };
    let rowNum = 2;
    for (const sub of obj.submissions || []) {
      // Remove #0 from discord_username
      let discord = (sub.discord_username || '').replace(/#0$/, '');
      sheet.addRow([discord, sub.display_name || '', sub.warlord || '']);
      rowNum++;
    }
  } else if (type === 'decks') {
    // Expect array of deck objects
    const arr = typeof json === 'string' ? JSON.parse(json) : json;
    let rowNum = 1;
    for (const deck of arr) {
      // Header for each deck, stacked user info
      sheet.addRow([`Event: ${deck.eventName || ''}`]);
      sheet.getRow(rowNum).font = { bold: true };
      rowNum++;
      sheet.addRow(['discord_username']);
      sheet.getRow(rowNum).font = { bold: true };
      rowNum++;
      let discord = (deck.discord_username || '').replace(/#0$/, '');
      sheet.addRow([discord]);
      rowNum++;
      sheet.addRow(['display_name']);
      sheet.getRow(rowNum).font = { bold: true };
      rowNum++;
      sheet.addRow([deck.display_name || '']);
      rowNum++;
      sheet.addRow(['warlord']);
      sheet.getRow(rowNum).font = { bold: true };
      rowNum++;
      sheet.addRow([deck.warlord || '']);
      rowNum++;
      const cardList = deck.cardList || {};
      for (const type in cardList) {
        sheet.addRow([type]);
        sheet.getRow(rowNum).font = { bold: true };
        rowNum++;
        // Starting Army cards (at top, warlord first)
        if (cardList[type].startingArmy && Object.keys(cardList[type].startingArmy).length > 0) {
          sheet.addRow(['Starting Army']);
          sheet.getRow(rowNum).font = { bold: true };
          rowNum++;
          // Warlord at top if present
          const saCards = Object.entries(cardList[type].startingArmy);
          let warlordCard = saCards.find(([card]) => card === deck.warlord);
          if (warlordCard) {
            sheet.addRow([warlordCard[0], warlordCard[1]]);
            rowNum++;
          }
          for (const [card, qty] of saCards) {
            if (card === deck.warlord) continue;
            sheet.addRow([card, qty]);
            rowNum++;
          }
          // Space between Starting Army and Main Deck
          sheet.addRow([]);
          rowNum++;
        }
        // Main Deck cards
        if (cardList[type].mainDeck && Object.keys(cardList[type].mainDeck).length > 0) {
          for (const [card, qty] of Object.entries(cardList[type].mainDeck)) {
            sheet.addRow([card, qty]);
            rowNum++;
          }
        }
      }
      // Blank line between decks
      sheet.addRow([]);
      rowNum++;
    }
  }
  const buffer = await workbook.xlsx.writeBuffer();
  return buffer;
}

// Download event file as CSV
app.get('/api/admin/download-event/:eventName', async (req, res) => {
  const eventName = req.params.eventName;
  const safeEventName = eventName.replace(/[^a-z0-9\-]+/gi, '-').toLowerCase();
  const eventPath = `backend/public/events/${safeEventName}.json`;
  try {
    const file = await getGithubFile(eventPath);
    if (!file) return res.status(404).send('Event file not found');
    const buffer = await jsonToExcel(file.content, 'event');
    res.setHeader('Content-Disposition', `attachment; filename="${safeEventName}.xlsx"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);
  } catch (err) {
    res.status(500).send('Error downloading event file');
  }
});

app.get('/api/admin/download-decks/:eventName', async (req, res) => {
  const eventName = req.params.eventName;
  const safeEventName = eventName.replace(/[^a-z0-9\-]+/gi, '-').toLowerCase();
  const decksPath = `backend/public/events/decks-${safeEventName}.json`;
  try {
    const file = await getGithubFile(decksPath);
    if (!file) return res.status(404).send('Decks file not found');
    const buffer = await jsonToExcel(file.content, 'decks');
    res.setHeader('Content-Disposition', `attachment; filename="decks-${safeEventName}.xlsx"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);
  } catch (err) {
    res.status(500).send('Error downloading decks file');
  }
});
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
  // Aggregate all cards across all types into a single object
  // Group cards by card type, create subgroups for Main Deck and Starting Army, and keep counts for each subtype
  const grouped = {};
  for (const type in cardList) {
    const cards = cardList[type];
    if (!grouped[type]) grouped[type] = {
      count: 0,
      mainDeck: {},
      startingArmy: {}
    };
    // Main Deck cards (excluding StartingArmy)
    for (const card in cards) {
      if (card === 'StartingArmy') continue;
      // The frontend is reporting the combined count as the main deck value, so subtract startingArmy from mainDeck
      const startingArmyCount = (cards['StartingArmy'] && cards['StartingArmy'][card]) || 0;
      const mainDeckCount = Math.max(cards[card] - startingArmyCount, 0);
      if (mainDeckCount > 0) {
        grouped[type].mainDeck[card] = mainDeckCount;
        grouped[type].count += mainDeckCount;
      }
    }
    // Starting Army cards
    if (cards['StartingArmy']) {
      for (const saCard in cards['StartingArmy']) {
        const saCount = cards['StartingArmy'][saCard];
        grouped[type].startingArmy[saCard] = saCount;
        grouped[type].count += saCount;
      }
    }
  }
  return grouped;
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