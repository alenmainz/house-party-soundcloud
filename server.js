// ============================================================
// MUSIC HOUSE PROTOTYPE — SoundCloud Edition — server.js
// ============================================================
// Rebuilt from the Spotify version to use SoundCloud instead:
//   - No per-user authentication cap (unlike Spotify's 5-user
//     Development Mode limit) — SoundCloud's only documented
//     limit is a shared 15,000 stream-plays/24hr budget per app,
//     which scales with real usage rather than gatekeeping login.
//   - SoundCloud tracks have a NATIVE genre field, so the whole
//     Deezer genre-lookup system is GONE — no more external
//     genre API needed at all. Genre filtering is just a check
//     against track.genre directly (and optionally a `genres=`
//     search param, though that filter has some documented
//     flakiness historically, so we double-check client-side
//     on the server too rather than trusting it blindly).
//   - Auth is OAuth 2.1 + PKCE (SoundCloud requirement), which
//     is a different flow shape than Spotify's OAuth2.
//   - Playback uses SoundCloud's stream URL + a native HTML5
//     <audio> element instead of a proprietary Web Playback SDK
//     (SoundCloud has no such SDK — it's just a direct stream
//     URL you set as an <audio> src, once authenticated).
//
// SETUP:
// 1. Get a SoundCloud Artist Pro subscription ($8.25/mo or
//    $99/yr) — required to register an app and get credentials.
// 2. Go to https://developers.soundcloud.com/, sign in, and
//    register a new app (Create a new application) to get your
//    Client ID and Client Secret.
// 3. Set redirect URI in your SoundCloud app settings to:
//      https://YOUR-RENDER-URL.onrender.com/callback
// 4. Set these environment variables in Render:
//      SOUNDCLOUD_CLIENT_ID
//      SOUNDCLOUD_CLIENT_SECRET
//      REDIRECT_URI  (e.g. https://YOUR-RENDER-URL.onrender.com/callback)
// 5. Build command: npm install   |   Start command: node server.js
// ============================================================

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const crypto = require('crypto');
const querystring = require('querystring');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const CLIENT_ID = process.env.SOUNDCLOUD_CLIENT_ID;
const CLIENT_SECRET = process.env.SOUNDCLOUD_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

const SC_AUTH_URL = 'https://secure.soundcloud.com/authorize';
const SC_TOKEN_URL = 'https://secure.soundcloud.com/oauth/token';
const SC_API_BASE = 'https://api.soundcloud.com';

// ============================================================
// HOUSE GENRE CONFIG
// SoundCloud tracks are tagged with a genre string directly by
// the uploader — no external genre-lookup service needed at all.
// This House accepts any track whose genre (case-insensitive)
// matches one of these. Add more Houses later by giving each
// its own accepted-genre list.
// ============================================================
const HOUSE_ACCEPTED_GENRES = [
  'dance', 'edm', 'electronic', 'house', 'deep house', 'tech house',
  'techno', 'trance', 'dubstep', 'drum & bass', 'drum and bass',
  'trap', 'future bass', 'bass', 'electro', 'progressive house',
  'hardstyle', 'big room',
];

function isGenreAllowed(genre) {
  if (!genre) return false;
  return HOUSE_ACCEPTED_GENRES.includes(genre.trim().toLowerCase());
}

// ============================================================
// PKCE HELPERS (required for SoundCloud's OAuth 2.1 flow)
// ============================================================
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// In-memory store of in-flight PKCE verifiers, keyed by state param.
// Cleared once used or after a timeout, so this doesn't grow forever.
const pendingAuth = new Map();

// ============================================================
// OAUTH FLOW
// ============================================================
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  pendingAuth.set(state, { codeVerifier, createdAt: Date.now() });

  // Clean up old pending entries (>10 min) occasionally
  for (const [key, val] of pendingAuth.entries()) {
    if (Date.now() - val.createdAt > 10 * 60 * 1000) pendingAuth.delete(key);
  }

  const authUrl = `${SC_AUTH_URL}?${querystring.stringify({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
  })}`;

  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error || !code) {
    return res.redirect(`/?error=${encodeURIComponent(error || 'access_denied')}`);
  }

  const pending = pendingAuth.get(state);
  if (!pending) {
    return res.redirect('/?error=invalid_or_expired_state');
  }
  pendingAuth.delete(state);

  try {
    const tokenResp = await fetch(SC_TOKEN_URL, {
      method: 'POST',
      headers: { 'accept': 'application/json; charset=utf-8', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: querystring.stringify({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code_verifier: pending.codeVerifier,
        code,
      }),
    });

    const data = await tokenResp.json();
    if (!data.access_token) {
      console.error('Token exchange failed:', data);
      return res.redirect('/?error=token_exchange_failed');
    }

    res.redirect(`/?access_token=${data.access_token}&refresh_token=${data.refresh_token}&expires_in=${data.expires_in}`);
  } catch (err) {
    console.error('Callback error:', err.message);
    res.redirect('/?error=server_error');
  }
});

app.post('/refresh_token', async (req, res) => {
  const { refresh_token } = req.body;
  try {
    const resp = await fetch(SC_TOKEN_URL, {
      method: 'POST',
      headers: { 'accept': 'application/json; charset=utf-8', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: querystring.stringify({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token,
      }),
    });
    const data = await resp.json();
    res.json(data);
  } catch (err) {
    console.error('Refresh error:', err.message);
    res.status(500).json({ error: 'refresh_failed' });
  }
});

// ============================================================
// SEARCH — hits SoundCloud's /tracks endpoint. We request the
// genres filter AND re-check genre client-side per result, since
// the genres= param has some documented historical flakiness.
// ============================================================
app.get('/search', async (req, res) => {
  const { q, access_token } = req.query;
  if (!q || !access_token) return res.status(400).json({ error: 'missing_params' });

  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');

  try {
    const resp = await fetch(
      `${SC_API_BASE}/tracks?${querystring.stringify({
        q,
        access: 'playable',
        limit: 15,
        linked_partitioning: true,
      })}`,
      { headers: { 'Authorization': `OAuth ${access_token}` } }
    );

    if (!resp.ok) {
      const body = await resp.text();
      console.error(`SoundCloud search failed (${resp.status}):`, body.slice(0, 300));
      return res.status(resp.status).json({ error: 'search_failed', detail: body.slice(0, 300) });
    }

    const data = await resp.json();
    const tracks = data.collection || [];

    const annotated = tracks.map(track => ({
      id: track.id,
      title: track.title,
      username: track.user ? track.user.username : 'Unknown artist',
      genre: track.genre || null,
      artworkUrl: track.artwork_url || (track.user && track.user.avatar_url) || null,
      durationMs: track.duration,
      streamable: track.streamable,
      houseAllowed: isGenreAllowed(track.genre),
    }));

    res.json({ tracks: annotated });
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: 'search_failed' });
  }
});

// ============================================================
// STREAM URL — resolves a track's actual streamable URL. The
// client sets this as an <audio> element's src. SoundCloud
// stream URLs require the access token appended as a param.
// ============================================================
app.get('/stream-url/:trackId', async (req, res) => {
  const { trackId } = req.params;
  const { access_token } = req.query;
  if (!access_token) return res.status(400).json({ error: 'missing_access_token' });

  try {
    const resp = await fetch(`${SC_API_BASE}/tracks/${trackId}/streams`, {
      headers: { 'Authorization': `OAuth ${access_token}` },
    });

    if (!resp.ok) {
      const body = await resp.text();
      console.error(`Stream resolve failed (${resp.status}):`, body.slice(0, 300));
      return res.status(resp.status).json({ error: 'stream_resolve_failed' });
    }

    const data = await resp.json();
    // Prefer progressive/http_mp3 stream if available, fall back to hls.
    const url = data.http_mp3_128_url || data.hls_mp3_128_url || data.preview_mp3_128_url;
    if (!url) return res.status(404).json({ error: 'no_stream_url_available' });

    res.json({ url });
  } catch (err) {
    console.error('Stream URL error:', err.message);
    res.status(500).json({ error: 'stream_resolve_failed' });
  }
});

// ---- In-memory House state ----
let houseState = {
  trackId: null,
  trackTitle: null,
  artistName: null,
  durationMs: 0,
  startedAt: null,
  roomSizeAtStart: 0,
};

let queue = [];
let comments = [];
let votes = {};
let skips = new Set();
let clientSessions = new Map();

// ---- WebSocket ----
wss.on('connection', (ws) => {
  const sessionId = Date.now() + '-' + Math.random().toString(36).slice(2, 10);
  clientSessions.set(ws, sessionId);

  console.log(`Client connected (${sessionId}). Total: ${clientSessions.size}`);

  ws.send(JSON.stringify({ type: 'SESSION_ID', payload: { sessionId } }));
  ws.send(JSON.stringify({ type: 'STATE_SYNC', payload: houseState }));
  ws.send(JSON.stringify({ type: 'QUEUE_SYNC', payload: queue }));
  ws.send(JSON.stringify({ type: 'COMMENTS_SYNC', payload: comments }));
  ws.send(JSON.stringify({ type: 'VOTES_SYNC', payload: tallyVotes() }));
  ws.send(JSON.stringify({ type: 'SKIPS_SYNC', payload: { count: skips.size, needed: skipsNeeded() } }));

  broadcastPresence();

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch (e) {
      return;
    }
    const sid = clientSessions.get(ws);

    if (msg.type === 'PLAY_TRACK') {
      startTrack(msg.payload);
    }

    if (msg.type === 'ADD_TO_QUEUE') {
      const track = msg.payload;
      if (!isGenreAllowed(track.genre)) {
        ws.send(JSON.stringify({
          type: 'QUEUE_REJECTED',
          payload: { name: track.title, reason: 'not_allowed_in_house' }
        }));
        return;
      }
      queue.push(track);
      broadcast({ type: 'QUEUE_SYNC', payload: queue });
      if (!houseState.trackId) advanceQueue();
    }

    if (msg.type === 'REMOVE_FROM_QUEUE') {
      queue = queue.filter((t, idx) => idx !== msg.payload.index);
      broadcast({ type: 'QUEUE_SYNC', payload: queue });
    }

    if (msg.type === 'ADD_COMMENT') {
      const comment = {
        id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
        username: (msg.payload.username || 'Anonymous').slice(0, 30),
        text: (msg.payload.text || '').slice(0, 280),
        timestamp: Date.now(),
        trackTitle: houseState.trackTitle || null,
        reactions: {},
      };
      comments.push(comment);
      if (comments.length > 200) comments = comments.slice(-200);
      broadcast({ type: 'NEW_COMMENT', payload: comment });
    }

    if (msg.type === 'TOGGLE_REACTION') {
      const { commentId, emoji } = msg.payload;
      const comment = comments.find(c => c.id === commentId);
      if (!comment) return;
      if (!comment.reactions[emoji]) comment.reactions[emoji] = [];
      const list = comment.reactions[emoji];
      const idx = list.indexOf(sid);
      if (idx === -1) list.push(sid); else list.splice(idx, 1);
      broadcast({ type: 'REACTION_UPDATE', payload: { commentId, reactions: comment.reactions } });
    }

    if (msg.type === 'CAST_VOTE') {
      if (['fire', 'x', 'neutral'].includes(msg.payload.vote)) {
        votes[sid] = msg.payload.vote;
        broadcast({ type: 'VOTES_SYNC', payload: tallyVotes() });
      }
    }

    if (msg.type === 'CAST_SKIP') {
      skips.add(sid);
      broadcast({ type: 'SKIPS_SYNC', payload: { count: skips.size, needed: skipsNeeded() } });
      checkSkipThreshold();
    }

    if (msg.type === 'REQUEST_SYNC') {
      ws.send(JSON.stringify({ type: 'STATE_SYNC', payload: houseState }));
    }
  });

  ws.on('close', () => {
    clientSessions.delete(ws);
    console.log(`Client disconnected. Total: ${clientSessions.size}`);
    broadcastPresence();
  });
});

function startTrack(track) {
  houseState = {
    trackId: track.id,
    trackTitle: track.title,
    artistName: track.username,
    durationMs: track.durationMs,
    startedAt: Date.now(),
    roomSizeAtStart: clientSessions.size,
  };
  votes = {};
  skips = new Set();
  broadcast({ type: 'STATE_SYNC', payload: houseState });
  broadcast({ type: 'VOTES_SYNC', payload: tallyVotes() });
  broadcast({ type: 'SKIPS_SYNC', payload: { count: 0, needed: skipsNeeded() } });
  console.log(`Now playing: ${houseState.trackTitle} by ${houseState.artistName} (room size: ${houseState.roomSizeAtStart})`);
}

function advanceQueue() {
  if (queue.length === 0) {
    houseState = { trackId: null, trackTitle: null, artistName: null, durationMs: 0, startedAt: null, roomSizeAtStart: 0 };
    votes = {};
    skips = new Set();
    broadcast({ type: 'STATE_SYNC', payload: houseState });
    broadcast({ type: 'VOTES_SYNC', payload: tallyVotes() });
    broadcast({ type: 'SKIPS_SYNC', payload: { count: 0, needed: 0 } });
    return;
  }
  const next = queue.shift();
  broadcast({ type: 'QUEUE_SYNC', payload: queue });
  startTrack(next);
}

function skipsNeeded() {
  if (!houseState.roomSizeAtStart) return 0;
  return Math.floor(houseState.roomSizeAtStart / 2) + 1;
}

function checkSkipThreshold() {
  if (!houseState.trackId) return;
  const needed = skipsNeeded();
  if (needed > 0 && skips.size >= needed) {
    console.log(`Skip threshold reached (${skips.size}/${houseState.roomSizeAtStart}). Advancing.`);
    advanceQueue();
  }
}

function tallyVotes() {
  const counts = { fire: 0, x: 0, neutral: 0 };
  Object.values(votes).forEach(v => { if (counts[v] !== undefined) counts[v]++; });
  return counts;
}

function broadcast(message) {
  const data = JSON.stringify(message);
  clientSessions.forEach((sid, client) => {
    if (client.readyState === WebSocket.OPEN) client.send(data);
  });
}

function broadcastPresence() {
  broadcast({ type: 'PRESENCE', payload: { count: clientSessions.size } });
}

// Scheduler: auto-advance when track naturally ends.
setInterval(() => {
  if (houseState.trackId && houseState.startedAt) {
    const elapsed = Date.now() - houseState.startedAt;
    if (elapsed > houseState.durationMs) {
      console.log('Track ended, advancing queue.');
      advanceQueue();
    }
  }
}, 2000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Music House (SoundCloud) prototype running on port ${PORT}`);
});
