const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const fs = require('node:fs');
const path = require('node:path');

const sessionPath = require.resolve('express-session');
require(sessionPath);
const originalSession = require.cache[sessionPath].exports;
require.cache[sessionPath].exports = () => (req, res, next) => {
  req.session = {
    user: {
      id: req.headers['x-test-user'] || 'player-1',
      username: req.headers['x-test-user'] || 'player-1',
      discriminator: '0'
    }
  };
  next();
};
const app = require('../index');
require.cache[sessionPath].exports = originalSession;

const files = new Map();
const originals = { get: axios.get, put: axios.put };
const eventListPath = 'backend/public/events/event_list.json';
const eventPath = 'backend/public/events/my-event.json';
const decksPath = 'backend/public/events/decks-my-event.json';
let server;
let baseUrl;
let failEventList = false;

before(async () => {
  axios.get = async (url) => {
    const filePath = new URL(url).pathname.split('/contents/')[1];
    if (failEventList && filePath === eventListPath) throw new Error('GitHub unavailable');
    if (!files.has(filePath)) {
      const error = new Error('Not found');
      error.response = { status: 404 };
      throw error;
    }
    return { data: { sha: 'test-sha', content: Buffer.from(files.get(filePath)).toString('base64') } };
  };
  axios.put = async (url, body) => {
    const filePath = new URL(url).pathname.split('/contents/')[1];
    files.set(filePath, Buffer.from(body.content, 'base64').toString('utf8'));
    return { data: {} };
  };
  server = await new Promise(resolve => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  axios.get = originals.get;
  axios.put = originals.put;
  if (server) await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
});

async function post(route, body, user = 'player-1') {
  const response = await fetch(baseUrl + route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-test-user': user },
    body: JSON.stringify(body)
  });
  return { status: response.status, body: await response.json() };
}

function stored(filePath) {
  return JSON.parse(files.get(filePath));
}

async function submit(warlord, user) {
  return post('/api/submit-deck', {
    eventName: 'My Event',
    warlord,
    cardList: { Character: { [warlord]: 1 } }
  }, user);
}

test('creation, toggles, uploads and withdrawal preserve the selected event policy', async () => {
  files.clear();
  files.set(eventListPath, '[]');
  const create = await post('/api/admin/create-event', {
    eventName: 'My Event', ruleset: 'test', startDate: '2020-01-01', endDate: '2030-01-01'
  });
  assert.equal(create.status, 200);
  assert.equal(stored(eventListPath)[0].keepAllDecks, false);

  assert.equal((await submit('Old')).status, 200);
  assert.equal((await submit('Other', 'player-2')).status, 200);
  assert.equal((await submit('Replacement')).status, 200);
  assert.deepEqual(stored(eventPath).submissions.map(s => s.warlord), ['Other', 'Replacement']);
  assert.deepEqual(stored(decksPath).map(d => d.warlord), ['Other', 'Replacement']);

  assert.equal((await post('/api/admin/event-deck-policy', { eventName: 'My Event', keepAllDecks: true })).status, 200);
  assert.equal(stored(eventListPath)[0].keepAllDecks, true);
  assert.equal((await submit('Second')).status, 200);
  assert.equal((await submit('Third')).status, 200);
  assert.deepEqual(stored(eventPath).submissions.map(s => s.warlord), ['Other', 'Replacement', 'Second', 'Third']);
  assert.deepEqual(stored(decksPath).map(d => d.warlord), ['Other', 'Replacement', 'Second', 'Third']);

  const withdrawal = await post('/api/submit-deck', {
    eventName: 'My Event', deckContents: [{ name: 'Withdraw from Event' }]
  });
  assert.equal(withdrawal.body.withdrawn, true);
  assert.deepEqual(stored(eventPath).submissions.map(s => s.warlord), ['Other']);
  assert.deepEqual(stored(decksPath).map(d => d.warlord), ['Other']);

  assert.equal((await submit('One')).status, 200);
  assert.equal((await submit('Two')).status, 200);
  assert.equal((await post('/api/admin/event-deck-policy', { eventName: 'My Event', keepAllDecks: false })).status, 200);
  assert.equal(stored(decksPath).length, 3);
  assert.equal((await submit('Final')).status, 200);
  assert.deepEqual(stored(eventPath).submissions.map(s => s.warlord), ['Other', 'Final']);
  assert.deepEqual(stored(decksPath).map(d => d.warlord), ['Other', 'Final']);
});

test('legacy events replace decks, and invalid or unavailable settings fail without writes', async () => {
  const events = stored(eventListPath);
  delete events[0].keepAllDecks;
  files.set(eventListPath, JSON.stringify(events));
  assert.equal((await submit('Legacy')).status, 200);
  assert.deepEqual(stored(decksPath).map(d => d.warlord), ['Other', 'Legacy']);

  const beforeEvent = files.get(eventPath);
  const beforeDecks = files.get(decksPath);
  assert.equal((await post('/api/admin/event-deck-policy', { eventName: 'My Event', keepAllDecks: 'true' })).status, 400);
  assert.equal((await post('/api/admin/event-deck-policy', { eventName: 'Missing', keepAllDecks: true })).status, 404);
  failEventList = true;
  assert.equal((await submit('Unavailable')).status, 500);
  failEventList = false;
  assert.equal(files.get(eventPath), beforeEvent);
  assert.equal(files.get(decksPath), beforeDecks);

  files.set(decksPath, 'invalid json');
  assert.equal((await submit('Invalid')).status, 500);
  assert.equal(files.get(eventPath), beforeEvent);
  assert.equal(files.get(decksPath), 'invalid json');
});

test('new events can start with keep-all enabled', async () => {
  const result = await post('/api/admin/create-event', {
    eventName: 'Another Event', ruleset: 'test', startDate: '2020-01-01', endDate: '2030-01-01', keepAllDecks: true
  });
  assert.equal(result.status, 200);
  assert.equal(stored(eventListPath).find(e => e.eventName === 'Another Event').keepAllDecks, true);
});

test('the user-decks endpoint returns every matching deck', async () => {
  const eventList = path.join(__dirname, '..', 'public', 'events', 'event_list.json');
  const deckFile = path.join(__dirname, '..', 'public', 'events', 'decks-my-event.json');
  const readFileSync = fs.readFileSync;
  const existsSync = fs.existsSync;
  fs.readFileSync = (file, ...args) => {
    if (file === eventList) return JSON.stringify([{ eventName: 'My Event', decklistFile: 'decks-my-event.json' }]);
    if (file === deckFile) return JSON.stringify([
      { discordId: 'player-1', warlord: 'One' },
      { discordId: 'player-1', warlord: 'Two' },
      { discordId: 'player-2', warlord: 'Other' }
    ]);
    return readFileSync.call(fs, file, ...args);
  };
  fs.existsSync = (file) => file === deckFile || existsSync.call(fs, file);
  try {
    const response = await fetch(baseUrl + '/api/user/decks');
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.deepEqual(result.events.map(event => event.deck.warlord), ['One', 'Two']);
  } finally {
    fs.readFileSync = readFileSync;
    fs.existsSync = existsSync;
  }
});
