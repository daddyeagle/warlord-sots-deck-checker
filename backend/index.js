// Express server for Discord OAuth2 login
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const axios = require('axios'); // Use one axios import
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const CARDS_REMOTE_BASE_URL = 'https://theaccordlands.com/assets/resources/';
const KNOWN_CARD_FILES = [
  'cards.e70a1eb5.json',
  'cards.76f06328.json',
  'cards.38a524ad.json',
  'cards.e1d32a9e.json',
  'cards.253921fb.json',
  'cards.725ee9dd.json',
  'cards.json'
];
const CARDS_LOCAL_PATH = path.join(__dirname, 'public', 'assets', 'resources', 'cards.json');

const app = express();
// Session Setup (move to top)
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace_this_secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/'
  }
}));

// Endpoint: Get all deck submissions for all events
app.get('/api/all-decks', (req, res) => {
  // Restrict to authenticated users only
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  const eventsDir = path.join(__dirname, 'public', 'events');
  const eventsPath = path.join(eventsDir, 'event_list.json');
  let eventList = [];
  try {
    eventList = JSON.parse(fs.readFileSync(eventsPath, 'utf8'));
  } catch (e) {
    eventList = [];
  }

  const results = [];
  const processedFiles = new Set();

  const addDeckFile = (deckFile, eventNameHint = null) => {
    if (!deckFile || processedFiles.has(deckFile)) return;
    const deckPath = path.join(eventsDir, deckFile);
    if (!fs.existsSync(deckPath)) return;

    let decks;
    try {
      decks = JSON.parse(fs.readFileSync(deckPath, 'utf8'));
    } catch (e) {
      return;
    }
    if (!Array.isArray(decks)) return;

    const inferredEventName =
      eventNameHint ||
      (decks[0] && typeof decks[0].event === 'string' ? decks[0].event : null) ||
      deckFile.replace(/^decks-/, '').replace(/\.json$/, '');

    results.push({ eventName: inferredEventName, decks });
    processedFiles.add(deckFile);
  };

  // Include only current admin-managed events from event_list.json.
  for (const event of eventList) {
    if (!event || event.hidden) continue;
    addDeckFile(event && event.decklistFile, event && event.eventName ? event.eventName : null);
  }

  res.json({ events: results });
});
const extractCardFiles = (text) => {
  if (!text || typeof text !== 'string') return [];
  const matches = text.match(/cards(?:\.[a-f0-9]{6,})?\.json/gi) || [];
  const unique = new Set();
  for (const match of matches) unique.add(match.toLowerCase());
  return [...unique];
};

async function fetchText(url) {
  try {
    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'Cache-Control': 'no-cache' }
    });
    if (response.status < 200 || response.status >= 300) return null;
    return typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
  } catch (_) {
    return null;
  }
}

async function inspectCandidate(fileName) {
  const url = CARDS_REMOTE_BASE_URL + fileName;
  const isJsonContentType = (contentType) =>
    typeof contentType === 'string' && contentType.toLowerCase().includes('application/json');
  try {
    const head = await axios.head(url, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'Cache-Control': 'no-cache' }
    });
    if (head.status >= 200 && head.status < 300) {
      if (!isJsonContentType(head.headers['content-type'])) return null;
      const modified = Date.parse(head.headers['last-modified'] || '') || 0;
      return { url, modified };
    }
  } catch (_) {
    // Some hosts block HEAD; continue with GET validation.
  }

  try {
    const get = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      headers: { 'Cache-Control': 'no-cache' }
    });
    if (get.status < 200 || get.status >= 300) return null;
    if (!isJsonContentType(get.headers['content-type'])) return null;
    const modified = Date.parse(get.headers['last-modified'] || '') || 0;
    return { url, modified };
  } catch (_) {
    return null;
  }
}

async function resolveLatestCardDataUrl() {
  const candidateSources = [
    CARDS_REMOTE_BASE_URL,
    `${CARDS_REMOTE_BASE_URL}index.html`,
    `${CARDS_REMOTE_BASE_URL}manifest.json`,
    `${CARDS_REMOTE_BASE_URL}asset-manifest.json`,
    'https://theaccordlands.com/manifest.json',
    'https://theaccordlands.com/asset-manifest.json'
  ];

  const discovered = [];
  for (const sourceUrl of candidateSources) {
    const text = await fetchText(sourceUrl);
    if (text) discovered.push(...extractCardFiles(text));
  }

  const orderedCandidates = [];
  const seenCandidates = new Set();
  for (const file of [...discovered, ...KNOWN_CARD_FILES]) {
    if (seenCandidates.has(file)) continue;
    seenCandidates.add(file);
    orderedCandidates.push(file);
  }

  if (orderedCandidates.length > 0) {
    const inspected = await Promise.all(orderedCandidates.map(inspectCandidate));
    const valid = inspected
      .map((value, index) => value ? { ...value, priority: index } : null)
      .filter(Boolean);

    if (valid.length > 0) {
      valid.sort((a, b) => {
        if (b.modified !== a.modified) return b.modified - a.modified;
        return a.priority - b.priority;
      });
      return valid[0].url;
    }
  }

  return CARDS_REMOTE_BASE_URL + KNOWN_CARD_FILES[0];
}

// Periodically download the latest card database from the remote source
async function updateCardDatabase() {
  try {
    const cardsRemoteUrl = await resolveLatestCardDataUrl();
    const response = await axios.get(cardsRemoteUrl, { timeout: 10000 });
    fs.mkdirSync(path.dirname(CARDS_LOCAL_PATH), { recursive: true });
    fs.writeFileSync(CARDS_LOCAL_PATH, JSON.stringify(response.data, null, 2), 'utf8');
    console.log(`Card database updated from remote source: ${cardsRemoteUrl}`);
  } catch (err) {
    console.error('Failed to update card database:', err.message);
  }
}

// Update every 6 hours
// Update every 48 hours
setInterval(updateCardDatabase, 48 * 60 * 60 * 1000);
// Initial update on server start
updateCardDatabase();

// API endpoint to serve local card database
app.get('/api/cards', (req, res) => {
  if (!fs.existsSync(CARDS_LOCAL_PATH)) {
    return res.status(404).json({ error: 'Card data not found' });
  }
  fs.readFile(CARDS_LOCAL_PATH, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'Failed to read card data' });
    res.setHeader('Content-Type', 'application/json');
    res.send(data);
  });
});

// Withdraw deck for event (remove from event and deck lists)
app.post('/api/withdraw-deck', async (req, res) => {
  try {
    if (!req.session || !req.session.user || !req.session.user.id) return res.status(401).json({ success: false, error: 'Not logged in' });
    const { eventName } = req.body || {};
    if (!eventName) return res.status(400).json({ success: false, error: 'Missing eventName' });
    const discordId = req.session.user.id;
    const usernameLower = req.session.user.username ? req.session.user.username.toLowerCase() : null;
    const displayNameLower = req.session.user.displayName ? req.session.user.displayName.toLowerCase() : null;
    const discordTagLower = (req.session.user.username && req.session.user.discriminator)
      ? `${req.session.user.username}#${req.session.user.discriminator}`.toLowerCase()
      : null;
    const isOwnedByUser = (record) => {
      if (!record || typeof record !== 'object') return false;
      if (record.discordId === discordId || record.username === discordId) return true;
      if (usernameLower && typeof record.username === 'string' && record.username.toLowerCase() === usernameLower) return true;
      if (discordTagLower && typeof record.discord_username === 'string' && record.discord_username.toLowerCase() === discordTagLower) return true;
      if (usernameLower && typeof record.discord_username === 'string' && record.discord_username.toLowerCase().startsWith(`${usernameLower}#`)) return true;
      if (displayNameLower && typeof record.display_name === 'string' && record.display_name.toLowerCase() === displayNameLower) return true;
      return false;
    };
    const decksPath = path.join(__dirname, 'public', 'events', `decks-${eventName}.json`);
    const eventPath = path.join(__dirname, 'public', 'events', `${eventName}.json`);
    let changed = false;
    // Remove from deck list
    if (fs.existsSync(decksPath)) {
      const decks = JSON.parse(fs.readFileSync(decksPath, 'utf8'));
      const newDecks = decks.filter(d => !isOwnedByUser(d));
      if (newDecks.length !== decks.length) {
        fs.writeFileSync(decksPath, JSON.stringify(newDecks, null, 2));
        changed = true;
      }
    }
    // Remove from event list
    if (fs.existsSync(eventPath)) {
      const eventEntries = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
      const entries = Array.isArray(eventEntries.submissions) ? eventEntries.submissions : eventEntries;
      const newEntries = entries.filter(d => !isOwnedByUser(d));
      if (newEntries.length !== entries.length) {
        if (Array.isArray(eventEntries.submissions)) {
          eventEntries.submissions = newEntries;
          fs.writeFileSync(eventPath, JSON.stringify(eventEntries, null, 2));
        } else {
          fs.writeFileSync(eventPath, JSON.stringify(newEntries, null, 2));
        }
        changed = true;
      }
    }
    if (changed) {
      res.json({ success: true });
    } else {
      res.json({ success: false, error: 'No entry found to withdraw' });
    }
  } catch (e) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});
const PORT = process.env.PORT || 8080;

// FIX 1: Trust ALL proxies (for Railway)
app.set('trust proxy', true);

// API for warlord_configuration.json (GET and POST)
app.get('/api/config', (req, res) => {
  const configPath = path.join(__dirname, 'warlord_configuration.json');
  fs.readFile(configPath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'Config not found' });
    res.setHeader('Content-Type', 'application/json');
    res.send(data);
  });
});

app.use(express.json({ limit: '2mb' }));

app.post('/api/config', (req, res) => {
  const configPath = path.join(__dirname, 'warlord_configuration.json');
  const configData = req.body;
  if (!configData || typeof configData !== 'object') {
    return res.status(400).json({ error: 'Invalid config data' });
  }
  fs.writeFile(configPath, JSON.stringify(configData, null, 2), 'utf8', async (err) => {
    if (err) return res.status(500).json({ error: 'Failed to write config' });
    // Push to GitHub as well
    try {
      const { putFile } = require('./github');
      await putFile('backend/warlord_configuration.json', configData, 'Update warlord_configuration.json via admin');
      res.json({ success: true, github: true });
    } catch (e) {
      console.error('GitHub update failed:', e.message);
      res.json({ success: true, github: false, error: 'Local update succeeded, GitHub update failed.' });
    }
  });
});

// Proxy for event_list.json
app.get('/events/event_list.json', (req, res) => {
  const eventListPath = path.join(__dirname, 'public', 'events', 'event_list.json');
  fs.readFile(eventListPath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'Event list not found' });
    res.setHeader('Content-Type', 'application/json');
    res.send(data);
  });
});

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
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/'
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Redirect /auth-success to main page after OAuth login
app.get('/auth-success', (req, res) => {
  res.redirect('/');
});

// Endpoint: Get submitted decks for logged-in user
app.get('/api/user/decks', (req, res) => {
  // Debug: log session user info
  console.log('DEBUG /api/user/decks session:', req.session.user);
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
    const eventsPath = path.join(__dirname, 'public', 'events', 'event_list.json');
  let eventList;
  try {
    eventList = JSON.parse(fs.readFileSync(eventsPath, 'utf8'));
  } catch (e) {
    return res.status(500).json({ error: 'Failed to load event list' });
  }
  const results = [];
  for (const event of eventList) {
      const deckFile = event.decklistFile;
    if (!deckFile) continue;
    const deckPath = path.join(__dirname, 'events', deckFile);
    if (!fs.existsSync(deckPath)) continue;
    let decks;
    try {
      decks = JSON.parse(fs.readFileSync(deckPath, 'utf8'));
    } catch (e) {
      continue;
    }
    // Debug: log deck file and keys
    console.log('DEBUG event:', event.eventName, 'deckFile:', deckFile);
    const { id, username, discriminator, displayName } = req.session.user;
    const userDeck = decks.find(d =>
      d.discordId === id ||
      d.discord_username === `${username}#${discriminator}` ||
      d.username === id ||
      d.username === username ||
      d.display_name === displayName ||
      (displayName && typeof d.display_name === 'string' && d.display_name.toLowerCase() === displayName.toLowerCase())
    );
    if (userDeck) {
      console.log('DEBUG matched deck:', userDeck);
      results.push({ eventName: event.eventName, deck: userDeck });
    }
  }
  res.json({ events: results });
});

// --- AUTHENTICATION ROUTES ---
// --- ADMIN DOWNLOAD ENDPOINTS ---
// Download event file
const jsonToCsv = (json, type) => {
  if (!json) return '';
  // Helper to create hyphen row matching the longest header row in the deck
  function hyphenRow(row, maxLen) {
    return [ '//' + '-'.repeat(maxLen - 2) ];
  }
  if (type === 'event') {
    const obj = typeof json === 'string' ? JSON.parse(json) : json;
    const rows = [];
    const header = ['discord_username', 'display_name', 'warlord'];
    rows.push(header);
    rows.push(hyphenRow(header));
    for (const sub of obj.submissions || []) {
      let discord = (sub.discord_username || '').replace(/#0$/, '');
      rows.push([
        discord,
        sub.display_name || '',
        sub.warlord || ''
      ]);
    }
    return rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  }
  if (type === 'decks') {
    const arr = typeof json === 'string' ? JSON.parse(json) : json;
    let rows = [];
    for (const deck of arr) {
      // Header for each deck: event name, month, year
      // Use 'event' and 'timestamp' fields for header, and include 'username' (discord_username) in user info
      let eventName = deck.event || '';
      let month = '';
      let year = '';
      if (deck.timestamp) {
        const date = new Date(deck.timestamp);
        if (!isNaN(date)) {
          month = date.toLocaleString('default', { month: 'long' });
          year = date.getFullYear();
        }
      }
      const eventHeader = [`// ${eventName}`, `// ${month}`, `// ${year}`];
      const userHeader = ['// discord_username', '// display_name', '// warlord'];
      // Find max header length for this deck
      let maxLen = Math.max(
        eventHeader.join(',').length,
        userHeader.join(',').length,
        ...Object.keys(deck.cardList || {}).map(type => (`// ${type}`).length),
        '// Starting Army'.length
      );
      rows.push(eventHeader);
      rows.push(hyphenRow(eventHeader, maxLen));
      rows.push(userHeader);
      rows.push(hyphenRow(userHeader, maxLen));
      // Use discord_username from event file
      let discord = (deck.discord_username || '').replace(/#0$/, '');
      rows.push([
        `// ${discord}`,
        `// ${deck.display_name || ''}`,
        `// ${deck.warlord || ''}`
      ]);
      const cardList = deck.cardList || {};
      let firstType = true;
      for (const type in cardList) {
        if (!firstType) rows.push([]); // Space between card types
        firstType = false;
        rows.push([`// ${type}`]);
        rows.push(hyphenRow([`// ${type}`], maxLen));
        // Starting Army cards (at top, warlord first)
        if (cardList[type].startingArmy && Object.keys(cardList[type].startingArmy).length > 0) {
          rows.push(['// Starting Army']);
          rows.push(hyphenRow(['// Starting Army'], maxLen));
          const saCards = Object.entries(cardList[type].startingArmy);
          let warlordCard = saCards.find(([card]) => card === deck.warlord);
          if (warlordCard) {
            rows.push([`${warlordCard[1]} ${warlordCard[0]}`]);
          }
          for (const [card, qty] of saCards) {
            if (card === deck.warlord) continue;
            rows.push([`${qty} ${card}`]);
          }
          // Space between Starting Army and Main Deck
          rows.push([]);
        }
        // Main Deck cards
        if (cardList[type].mainDeck && Object.keys(cardList[type].mainDeck).length > 0) {
          for (const [card, qty] of Object.entries(cardList[type].mainDeck)) {
            rows.push([`${qty} ${card}`]);
          }
        }
      }
      // Blank line between decks
      rows.push([]);
    }
    // Custom CSV: do not quote header rows or card lines; only quote user info if needed
    return rows.map((r, i) => {
      // Remove quotes from header rows (start with //)
      if (r.every(v => typeof v === 'string' && v.startsWith('//'))) {
        return r.join(',');
      }
      // Card lines (single value, no quotes)
      if (r.length === 1) {
        return r[0];
      }
      // User info (multi-value, keep quotes for commas in display_name/warlord)
      return r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');
    }).join('\n');
  }
  return '';
}

// Download event file as CSV
app.get('/api/admin/download-event/:eventName', async (req, res) => {
  const eventName = req.params.eventName;
  const safeEventName = eventName.replace(/[^a-z0-9\-]+/gi, '-').toLowerCase();
  const eventPath = `backend/public/events/${safeEventName}.json`;
  try {
    const file = await getGithubFile(eventPath);
    if (!file) return res.status(404).send('Event file not found');
    const csv = jsonToCsv(file.content, 'event');
    res.setHeader('Content-Disposition', `attachment; filename="${safeEventName}.csv"`);
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
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
    const csv = jsonToCsv(file.content, 'decks');
    res.setHeader('Content-Disposition', `attachment; filename="decks-${safeEventName}.csv"`);
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
  } catch (err) {
    res.status(500).send('Error downloading decks file');
  }
});
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://warlord-sots-deck-checker-production.up.railway.app/api/auth/discord/callback';

app.get('/api/auth/discord', (req, res) => {
  // Support redirect parameter
  const redirect = req.query.redirect || '/';
  req.session.loginRedirect = redirect;
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
      let redirectPath = req.session.loginRedirect || '/';
      req.session.loginRedirect = undefined;
      if (typeof redirectPath !== 'string') redirectPath = '/';
      if (!redirectPath.startsWith('/')) redirectPath = '/';
      redirectPath = '/' + redirectPath.replace(/^\/+/, '');
      if (redirectPath === '/' || redirectPath === '/auth-success') {
        redirectPath = '/';
      }
      req.session.save((err) => {
        if (err) return res.status(500).send("Session save failed");
        if (process.env.FRONTEND_ORIGIN) {
          const base = process.env.FRONTEND_ORIGIN.replace(/\/+$/, '');
          res.redirect(`${base}${redirectPath}`);
        } else {
          res.redirect(redirectPath);
        }
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
// --- EVENT ADMIN ENDPOINTS ---
const EVENT_LIST_PATH = 'backend/public/events/event_list.json';

// Helper: Load event list
async function loadEventList() {
  const file = await getGithubFile(EVENT_LIST_PATH);
  if (!file) return [];
  try { return JSON.parse(file.content); } catch (e) { return []; }
}

// Helper: Save event list
async function saveEventList(events, sha = null) {
  await putGithubFile(EVENT_LIST_PATH, events, 'Update event list', sha);
}

// Create new event
app.post('/api/admin/create-event', async (req, res) => {
  const { eventName, ruleset, startDate, endDate } = req.body;
  if (!eventName || !ruleset || !startDate || !endDate) return res.status(400).json({ error: 'Missing fields' });
  const safeEventName = eventName.replace(/[^a-z0-9\-]+/gi, '-').toLowerCase();
  const decklistFile = `decks-${safeEventName}.json`;
  const submissionFile = `${safeEventName}.json`;
  try {
    let requiredTextFieldLabel = '';
    let requiredTextFieldPlaceholder = '';
    try {
      const configPath = path.join(__dirname, 'warlord_configuration.json');
      const configRaw = fs.readFileSync(configPath, 'utf8');
      const configObj = JSON.parse(configRaw);
      const rulesetConfig = configObj && configObj.rulesets ? configObj.rulesets[ruleset] : null;
      const requiredMeta = rulesetConfig ? rulesetConfig.requiredEventTextField : null;
      requiredTextFieldLabel = typeof requiredMeta === 'string'
        ? requiredMeta.trim()
        : (requiredMeta && typeof requiredMeta.label === 'string' ? requiredMeta.label.trim() : '');
      requiredTextFieldPlaceholder = requiredMeta && typeof requiredMeta === 'object' && typeof requiredMeta.placeholder === 'string'
        ? requiredMeta.placeholder.trim()
        : '';
    } catch (e) {
      // Ignore malformed config here and continue creating the event.
    }

    // Create empty decklist and submission files if not exist
    for (const file of [decklistFile, submissionFile]) {
      const path = `backend/public/events/${file}`;
      const exists = await getGithubFile(path);
      if (!exists) await putGithubFile(path, file === decklistFile ? [] : { eventName, submissions: [] }, `Create ${file}`);
    }
    // Update event list
    const eventListFile = await getGithubFile(EVENT_LIST_PATH);
    let events = [];
    let sha = null;
    if (eventListFile) { sha = eventListFile.sha; try { events = JSON.parse(eventListFile.content); } catch (e) {} }
    if (!Array.isArray(events)) events = [];
    // Remove any previous event with same name
    events = events.filter(ev => ev.eventName !== eventName);
    const eventObj = { eventName, ruleset, startDate, endDate, decklistFile, submissionFile, hidden: false };
    if (requiredTextFieldLabel) {
      eventObj.requiredTextFieldLabel = requiredTextFieldLabel;
      if (requiredTextFieldPlaceholder) eventObj.requiredTextFieldPlaceholder = requiredTextFieldPlaceholder;
    }
    events.push(eventObj);
    await saveEventList(events, sha);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create event', details: err.message });
  }
});

// List events
app.get('/api/admin/list-events', async (req, res) => {
  try {
    const events = await loadEventList();
    res.json({ events });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list events' });
  }
});

// Delete event
app.post('/api/admin/delete-event', async (req, res) => {
  const { eventName } = req.body;
  if (!eventName) return res.status(400).json({ error: 'Missing eventName' });
  try {
    // Remove from event list
    const eventListFile = await getGithubFile(EVENT_LIST_PATH);
    let events = [];
    let sha = null;
    if (eventListFile) { sha = eventListFile.sha; try { events = JSON.parse(eventListFile.content); } catch (e) {} }
    events = events.filter(ev => ev.eventName !== eventName);
    await saveEventList(events, sha);
    // Optionally: delete decklist and submission files (not strictly necessary, but can be added)
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// Hide/unhide event
app.post('/api/admin/hide-event', async (req, res) => {
  const { eventName } = req.body;
  if (!eventName) return res.status(400).json({ error: 'Missing eventName' });
  try {
    const eventListFile = await getGithubFile(EVENT_LIST_PATH);
    let events = [];
    let sha = null;
    if (eventListFile) { sha = eventListFile.sha; try { events = JSON.parse(eventListFile.content); } catch (e) {} }
    events = events.map(ev => ev.eventName === eventName ? { ...ev, hidden: !ev.hidden } : ev);
    await saveEventList(events, sha);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to hide/unhide event' });
  }
});
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
    // Debug: log incoming request body for troubleshooting
    console.log('submit-deck req.body:', JSON.stringify(req.body));
  // 1. Auth Check
  if (!req.session.user) return res.status(401).json({ success: false, error: 'Not authenticated' });
  

  // 2. Destructure inputs (FIXED ORDER)
  const { eventName, warlord, cardList, deckContents, requiredTextFieldValue } = req.body;

  // Special case: Withdraw logic (must come before required fields check)
  let isWithdraw = false;
  // Robust: check deckContents, warlord, or cardList for 'Withdraw'
  const withdrawKeyword = 'withdraw from event';
  if (Array.isArray(deckContents) && deckContents.length === 1 && typeof deckContents[0].name === 'string') {
    isWithdraw = deckContents[0].name.trim().toLowerCase() === withdrawKeyword;
  } else if (typeof warlord === 'string' && warlord.trim().toLowerCase() === withdrawKeyword) {
    isWithdraw = true;
  } else if (cardList && typeof cardList === 'object' && Object.keys(cardList).length === 1 && Object.keys(cardList)[0].toLowerCase() === withdrawKeyword) {
    isWithdraw = true;
  }

  // Prepare User Data (needed for withdraw logic and after)
  const username = req.session.user.id;
  const discordId = req.session.user.id;
  const discordUsername = `${req.session.user.username}#${req.session.user.discriminator}`;
  const usernameLower = req.session.user.username ? req.session.user.username.toLowerCase() : null;
  const displayNameLower = req.session.user.displayName ? req.session.user.displayName.toLowerCase() : null;
  const discordTagLower = discordUsername.toLowerCase();
  const displayName = req.session.user.displayName || req.session.user.username;
  const isOwnedByUser = (record) => {
    if (!record || typeof record !== 'object') return false;
    if (record.discordId === discordId || record.username === discordId) return true;
    if (usernameLower && typeof record.username === 'string' && record.username.toLowerCase() === usernameLower) return true;
    if (discordTagLower && typeof record.discord_username === 'string' && record.discord_username.toLowerCase() === discordTagLower) return true;
    if (usernameLower && typeof record.discord_username === 'string' && record.discord_username.toLowerCase().startsWith(`${usernameLower}#`)) return true;
    if (displayNameLower && typeof record.display_name === 'string' && record.display_name.toLowerCase() === displayNameLower) return true;
    return false;
  };

  if (isWithdraw) {
    if (!eventName) {
      return res.status(400).json({ success: false, withdrawn: true, message: 'Missing eventName' });
    }
    const safeEventName = eventName.replace(/[^a-z0-9\-]+/gi, '-').toLowerCase();
    const eventPath = `backend/public/events/${safeEventName}.json`;
    const decksPath = `backend/public/events/decks-${safeEventName}.json`;
    let changed = false;
    // Remove from event file
    try {
      const existingEvent = await getGithubFile(eventPath);
      if (existingEvent) {
        let eventObj = JSON.parse(existingEvent.content);
        if (Array.isArray(eventObj.submissions)) {
          const newSubs = eventObj.submissions.filter(sub => !isOwnedByUser(sub));
          if (newSubs.length !== eventObj.submissions.length) {
            eventObj.submissions = newSubs;
            await putGithubFile(eventPath, eventObj, `Withdraw from event ${eventName} by ${discordUsername}`, existingEvent.sha);
            changed = true;
          }
        }
      }
    } catch (e) { /* ignore */ }
    // Remove from decks file
    try {
      const existingDecks = await getGithubFile(decksPath);
      if (existingDecks) {
        let decksArr = JSON.parse(existingDecks.content);
        if (Array.isArray(decksArr)) {
          const newDecks = decksArr.filter(d => !isOwnedByUser(d));
          if (newDecks.length !== decksArr.length) {
            await putGithubFile(decksPath, newDecks, `Withdraw deck from event ${eventName} by ${discordUsername}`, existingDecks.sha);
            changed = true;
          }
        }
      }
    } catch (e) { /* ignore */ }
    if (changed) {
      return res.json({ success: true, withdrawn: true, message: 'You have withdrawn from the event.' });
    } else {
      return res.json({ success: false, withdrawn: true, message: 'No entry found to withdraw.' });
    }
  }

  // 3. Validation
  if (!eventName || !warlord || !cardList) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }
  // Load event list to get startDate
  const eventListPath = path.join(__dirname, 'public', 'events', 'event_list.json');
  let eventStartDate = null;
  let eventRequiredTextFieldLabel = null;
  let eventRulesetKey = null;
  try {
    const eventListRaw = fs.readFileSync(eventListPath, 'utf8');
    const eventList = JSON.parse(eventListRaw);
    const eventMeta = eventList.find(e => e.eventName === eventName);
    if (eventMeta) {
      if (eventMeta.startDate) eventStartDate = eventMeta.startDate;
      if (typeof eventMeta.ruleset === 'string' && eventMeta.ruleset.trim()) {
        eventRulesetKey = eventMeta.ruleset.trim();
      }
      if (typeof eventMeta.requiredTextFieldLabel === 'string' && eventMeta.requiredTextFieldLabel.trim()) {
        eventRequiredTextFieldLabel = eventMeta.requiredTextFieldLabel.trim();
      }
    }
  } catch (e) { /* ignore, fallback to normal timestamp */ }

  if (!eventRequiredTextFieldLabel && eventRulesetKey) {
    try {
      const configPath = path.join(__dirname, 'warlord_configuration.json');
      const configRaw = fs.readFileSync(configPath, 'utf8');
      const configObj = JSON.parse(configRaw);
      const rs = configObj && configObj.rulesets ? configObj.rulesets[eventRulesetKey] : null;
      const requiredMeta = rs ? rs.requiredEventTextField : null;
      const fallbackLabel = typeof requiredMeta === 'string'
        ? requiredMeta.trim()
        : (requiredMeta && typeof requiredMeta.label === 'string' ? requiredMeta.label.trim() : '');
      if (fallbackLabel) eventRequiredTextFieldLabel = fallbackLabel;
    } catch (e) {
      // Ignore config read errors and continue without fallback label.
    }
  }

  const normalizedRequiredTextFieldValue = typeof requiredTextFieldValue === 'string'
    ? requiredTextFieldValue.trim()
    : '';
  if (eventRequiredTextFieldLabel && normalizedRequiredTextFieldValue.length < 4) {
    return res.status(400).json({
      success: false,
      error: `Missing required field: ${eventRequiredTextFieldLabel} (minimum 4 characters)`
    });
  }

  const now = new Date();
  let timestamp = now.toISOString();
  if (eventStartDate) {
    const start = new Date(eventStartDate);
    if (!isNaN(start) && now < start) {
      timestamp = start.toISOString();
    }
  }

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
    eventObj.submissions = eventObj.submissions.filter(sub => !isOwnedByUser(sub));
    
    eventObj.submissions.push({
      warlord,
      username, // Discord ID (legacy key)
      discordId,
      discord_username: discordUsername,
      display_name: displayName,
      timestamp,
      ...(eventRequiredTextFieldLabel ? {
        requiredTextFieldLabel: eventRequiredTextFieldLabel,
        requiredTextFieldValue: normalizedRequiredTextFieldValue
      } : {}),
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
    decksArr = decksArr.filter(d => !isOwnedByUser(d));

    // Append NEW deck (include discord_username for admin export)
    decksArr.push({
      username,
      discordId,
      discord_username: discordUsername,
      event: eventName,
      warlord,
      display_name: displayName,
      timestamp,
      ...(eventRequiredTextFieldLabel ? {
        requiredTextFieldLabel: eventRequiredTextFieldLabel,
        requiredTextFieldValue: normalizedRequiredTextFieldValue
      } : {}),
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