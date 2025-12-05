// backend/github.js
// Helper for GitHub API deck/event updates (server-side)
const axios = require('axios');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const OWNER = 'daddyeagle';
const REPO = 'warlord-sots-deck-checker';
const BRANCH = 'deploy-docs';

async function getFile(path) {
  const url = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}?ref=${BRANCH}`;
  const headers = { Authorization: `token ${GITHUB_TOKEN}`, Accept: 'application/vnd.github.v3.raw' };
  try {
    const res = await axios.get(url, { headers });
    return { content: res.data, sha: res.headers['etag'] };
  } catch (e) {
    if (e.response && e.response.status === 404) return { content: null, sha: null };
    throw e;
  }
}

async function putFile(path, obj, message) {
  // Always fetch latest sha
  const getUrl = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}?ref=${BRANCH}`;
  const putUrl = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}`;
  const headers = { Authorization: `token ${GITHUB_TOKEN}`, Accept: 'application/vnd.github.v3+json' };
  let sha = undefined;
  try {
    const res = await axios.get(getUrl, { headers });
    if (res.data && res.data.sha) sha = res.data.sha;
  } catch (e) { /* ignore 404 */ }
  const content = Buffer.from(JSON.stringify(obj, null, 2)).toString('base64');
  const body = { message, content, branch: BRANCH };
  if (sha) body.sha = sha;
  const putRes = await axios.put(putUrl, body, { headers });
  return putRes.data;
}

module.exports = { getFile, putFile };
