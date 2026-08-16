// ============================================================
// MUSIC HOUSE PROTOTYPE — SoundCloud Edition
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

// ============================================================
// SOUNDCLOUD CONFIG
// ============================================================

const CLIENT_ID = process.env.SOUNDCLOUD_CLIENT_ID;
const CLIENT_SECRET = process.env.SOUNDCLOUD_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

const SC_AUTH_URL = 'https://secure.soundcloud.com/authorize';
const SC_TOKEN_URL = 'https://secure.soundcloud.com/oauth/token';
const SC_API_BASE = 'https://api.soundcloud.com';

// ============================================================
// HOUSE GENRE CONFIG
// ============================================================

const HOUSE_ACCEPTED_GENRES = [
  'dance',
  'edm',
  'electronic',
  'house',
  'deep house',
  'tech house',
  'techno',
  'trance',
  'dubstep',
  'drum & bass',
  'drum and bass',
  'trap',
  'future bass',
  'bass',
  'electro',
  'progressive house',
  'hardstyle',
  'big room',
];

function isGenreAllowed(genre) {
  if (!genre) return false;

  return HOUSE_ACCEPTED_GENRES.includes(
    genre.trim().toLowerCase()
  );
}

// ============================================================
// PKCE HELPERS
// ============================================================

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}

const pendingAuth = new Map();

// ============================================================
// OAUTH
// ============================================================

app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');

  const codeVerifier = generateCodeVerifier();

  const codeChallenge =
    generateCodeChallenge(codeVerifier);

  pendingAuth.set(state, {
    codeVerifier,
    createdAt: Date.now(),
  });

  // Remove old auth requests.
  for (const [key, value] of pendingAuth.entries()) {
    if (Date.now() - value.createdAt > 10 * 60 * 1000) {
      pendingAuth.delete(key);
    }
  }

  const authUrl =
    `${SC_AUTH_URL}?` +
    querystring.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });

  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error || !code) {
    return res.redirect(
      `/?error=${encodeURIComponent(
        error || 'access_denied'
      )}`
    );
  }

  const pending = pendingAuth.get(state);

  if (!pending) {
    return res.redirect(
      '/?error=invalid_or_expired_state'
    );
  }

  pendingAuth.delete(state);

  try {
    const tokenResp = await fetch(SC_TOKEN_URL, {
      method: 'POST',

      headers: {
        accept: 'application/json; charset=utf-8',

        'Content-Type':
          'application/x-www-form-urlencoded',
      },

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

    if (!tokenResp.ok || !data.access_token) {
      console.error(
        'SoundCloud token exchange failed:',
        data
      );

      return res.redirect(
        '/?error=token_exchange_failed'
      );
    }

    const params = new URLSearchParams();

    params.set(
      'access_token',
      data.access_token
    );

    if (data.refresh_token) {
      params.set(
        'refresh_token',
        data.refresh_token
      );
    }

    if (data.expires_in) {
      params.set(
        'expires_in',
        String(data.expires_in)
      );
    }

    res.redirect(
      `/?${params.toString()}`
    );
  } catch (err) {
    console.error(
      'Callback error:',
      err
    );

    res.redirect(
      '/?error=server_error'
    );
  }
});

// ============================================================
// REFRESH TOKEN
// ============================================================

app.post('/refresh_token', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error: 'missing_refresh_token',
    });
  }

  try {
    const response = await fetch(SC_TOKEN_URL, {
      method: 'POST',

      headers: {
        accept: 'application/json; charset=utf-8',

        'Content-Type':
          'application/x-www-form-urlencoded',
      },

      body: querystring.stringify({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error(
        'SoundCloud token refresh failed:',
        data
      );

      return res
        .status(response.status)
        .json(data);
    }

    res.json(data);
  } catch (err) {
    console.error(
      'Refresh error:',
      err
    );

    res.status(500).json({
      error: 'refresh_failed',
    });
  }
});

// ============================================================
// SEARCH
// ============================================================

app.get('/search', async (req, res) => {
  const { q, access_token } = req.query;

  if (!q || !access_token) {
    return res.status(400).json({
      error: 'missing_params',
    });
  }

  res.set(
    'Cache-Control',
    'no-store, no-cache, must-revalidate'
  );

  try {
    const url =
      `${SC_API_BASE}/tracks?` +
      querystring.stringify({
        q,
        access: 'playable',
        limit: 15,
        linked_partitioning: true,
      });

    const response = await fetch(url, {
      headers: {
        Authorization:
          `OAuth ${access_token}`,
      },
    });

    if (!response.ok) {
      const body =
        await response.text();

      console.error(
        `SoundCloud search failed (${response.status}):`,
        body.slice(0, 500)
      );

      return res
        .status(response.status)
        .json({
          error: 'search_failed',
          detail: body.slice(0, 500),
        });
    }

    const data =
      await response.json();

    const tracks =
      data.collection || [];

    const annotated =
      tracks.map((track) => ({
        id: track.id,

        urn:
          track.urn ||
          null,

        title:
          track.title,

        username:
          track.user
            ? track.user.username
            : 'Unknown artist',

        genre:
          track.genre || null,

        artworkUrl:
          track.artwork_url ||
          (
            track.user &&
            track.user.avatar_url
          ) ||
          null,

        durationMs:
          track.duration,

        streamable:
          track.streamable,

        access:
          track.access,

        houseAllowed:
          isGenreAllowed(
            track.genre
          ),
      }));

    res.json({
      tracks: annotated,
    });
  } catch (err) {
    console.error(
      'Search error:',
      err
    );

    res.status(500).json({
      error: 'search_failed',
    });
  }
});

// ============================================================
// CURRENT SOUNDCLOUD STREAM RESOLVER
//
// IMPORTANT:
//
// We DO NOT use:
//   /tracks/:id/streams
//
// We DO NOT use:
//   http_mp3_128_url
//
// SoundCloud's current documented playback endpoint is:
//
//   GET /tracks/:trackId/stream
//
// It returns/redirects us to the current signed HLS playback
// resource.
//
// We return that URL to HLS.js in the browser.
// ============================================================

app.get('/stream-url/:trackId', async (req, res) => {
  const { trackId } = req.params;
  const { access_token } = req.query;

  if (!access_token) {
    return res.status(400).json({
      error: 'missing_access_token',
    });
  }

  try {
    console.log(
      `Resolving AAC HLS stream for track ${trackId}`
    );

    const response = await fetch(
      `${SC_API_BASE}/tracks/${encodeURIComponent(trackId)}/streams`,
      {
        method: 'GET',

        headers: {
          Authorization: `OAuth ${access_token}`,
          Accept: 'application/json',
        },

        redirect: 'follow',
      }
    );

    const body = await response.text();

    console.log(
      `SoundCloud /streams response: ${response.status}`
    );

    if (!response.ok) {
      console.error(
        `SoundCloud streams failed (${response.status}):`,
        body.slice(0, 1000)
      );

      return res.status(response.status).json({
        error: 'stream_resolve_failed',
        status: response.status,
        detail: body.slice(0, 500),
      });
    }

    let data;

    try {
      data = JSON.parse(body);
    } catch (err) {
      console.error(
        'SoundCloud returned non-JSON streams response:',
        body.slice(0, 1000)
      );

      return res.status(502).json({
        error: 'invalid_stream_response',
      });
    }

    console.log(
      'Available SoundCloud streams:',
      Object.keys(data)
    );

    /*
      SoundCloud's modern API playback format is AAC over HLS.

      Prefer 160 kbps AAC.
      Fall back to 96 kbps AAC if necessary.
    */

    const streamUrl =
      data.hls_aac_160_url ||
      data.hls_aac_96_url;

    if (!streamUrl) {
      console.error(
        'No AAC HLS stream found:',
        data
      );

      return res.status(404).json({
        error: 'no_aac_hls_stream',
        available: Object.keys(data),
      });
    }

    console.log(
      'AAC HLS stream resolved successfully:',
      streamUrl
    );

    return res.json({
      url: streamUrl,
      type: 'hls',
    });

  } catch (err) {
    console.error(
      'Stream resolver exception:',
      err
    );

    return res.status(500).json({
      error: 'stream_resolve_failed',
      detail: err.message,
    });
  }
});

// ============================================================
// HOUSE STATE
// ============================================================

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

let skips =
  new Set();

let clientSessions =
  new Map();

// ============================================================
// WEBSOCKETS
// ============================================================

wss.on('connection', (ws) => {
  const sessionId =
    Date.now() +
    '-' +
    Math.random()
      .toString(36)
      .slice(2, 10);

  clientSessions.set(
    ws,
    sessionId
  );

  console.log(
    `Client connected (${sessionId}). Total: ${clientSessions.size}`
  );

  ws.send(
    JSON.stringify({
      type: 'SESSION_ID',

      payload: {
        sessionId,
      },
    })
  );

  ws.send(
    JSON.stringify({
      type: 'STATE_SYNC',
      payload: houseState,
    })
  );

  ws.send(
    JSON.stringify({
      type: 'QUEUE_SYNC',
      payload: queue,
    })
  );

  ws.send(
    JSON.stringify({
      type: 'COMMENTS_SYNC',
      payload: comments,
    })
  );

  ws.send(
    JSON.stringify({
      type: 'VOTES_SYNC',
      payload: tallyVotes(),
    })
  );

  ws.send(
    JSON.stringify({
      type: 'SKIPS_SYNC',

      payload: {
        count:
          skips.size,

        needed:
          skipsNeeded(),
      },
    })
  );

  broadcastPresence();

  ws.on('message', (raw) => {
    let msg;

    try {
      msg =
        JSON.parse(raw);
    } catch {
      return;
    }

    const sid =
      clientSessions.get(ws);

    // --------------------------------------------------------
    // PLAY TRACK
    // --------------------------------------------------------

    if (
      msg.type ===
      'PLAY_TRACK'
    ) {
      startTrack(
        msg.payload
      );
    }

    // --------------------------------------------------------
    // QUEUE
    // --------------------------------------------------------

    if (
      msg.type ===
      'ADD_TO_QUEUE'
    ) {
      const track =
        msg.payload;

      if (
        !isGenreAllowed(
          track.genre
        )
      ) {
        ws.send(
          JSON.stringify({
            type:
              'QUEUE_REJECTED',

            payload: {
              name:
                track.title,

              reason:
                'not_allowed_in_house',
            },
          })
        );

        return;
      }

      queue.push(track);

      broadcast({
        type:
          'QUEUE_SYNC',

        payload:
          queue,
      });

      if (
        !houseState.trackId
      ) {
        advanceQueue();
      }
    }

    if (
      msg.type ===
      'REMOVE_FROM_QUEUE'
    ) {
      queue =
        queue.filter(
          (track, idx) =>
            idx !==
            msg.payload.index
        );

      broadcast({
        type:
          'QUEUE_SYNC',

        payload:
          queue,
      });
    }

    // --------------------------------------------------------
    // COMMENTS
    // --------------------------------------------------------

    if (
      msg.type ===
      'ADD_COMMENT'
    ) {
      const comment = {
        id:
          Date.now() +
          '-' +
          Math.random()
            .toString(36)
            .slice(2, 8),

        username:
          (
            msg.payload.username ||
            'Anonymous'
          ).slice(
            0,
            30
          ),

        text:
          (
            msg.payload.text ||
            ''
          ).slice(
            0,
            280
          ),

        timestamp:
          Date.now(),

        trackTitle:
          houseState.trackTitle ||
          null,

        reactions: {},
      };

      comments.push(
        comment
      );

      if (
        comments.length >
        200
      ) {
        comments =
          comments.slice(
            -200
          );
      }

      broadcast({
        type:
          'NEW_COMMENT',

        payload:
          comment,
      });
    }

    // --------------------------------------------------------
    // REACTIONS
    // --------------------------------------------------------

    if (
      msg.type ===
      'TOGGLE_REACTION'
    ) {
      const {
        commentId,
        emoji,
      } =
        msg.payload;

      const comment =
        comments.find(
          (c) =>
            c.id ===
            commentId
        );

      if (!comment) return;

      if (
        !comment.reactions[
          emoji
        ]
      ) {
        comment.reactions[
          emoji
        ] = [];
      }

      const list =
        comment.reactions[
          emoji
        ];

      const idx =
        list.indexOf(
          sid
        );

      if (
        idx === -1
      ) {
        list.push(
          sid
        );
      } else {
        list.splice(
          idx,
          1
        );
      }

      broadcast({
        type:
          'REACTION_UPDATE',

        payload: {
          commentId,

          reactions:
            comment.reactions,
        },
      });
    }

    // --------------------------------------------------------
    // VOTES
    // --------------------------------------------------------

    if (
      msg.type ===
      'CAST_VOTE'
    ) {
      if (
        [
          'fire',
          'x',
          'neutral',
        ].includes(
          msg.payload.vote
        )
      ) {
        votes[sid] =
          msg.payload.vote;

        broadcast({
          type:
            'VOTES_SYNC',

          payload:
            tallyVotes(),
        });
      }
    }

    // --------------------------------------------------------
    // SKIPS
    // --------------------------------------------------------

    if (
      msg.type ===
      'CAST_SKIP'
    ) {
      skips.add(
        sid
      );

      broadcast({
        type:
          'SKIPS_SYNC',

        payload: {
          count:
            skips.size,

          needed:
            skipsNeeded(),
        },
      });

      checkSkipThreshold();
    }

    // --------------------------------------------------------
    // RESYNC
    // --------------------------------------------------------

    if (
      msg.type ===
      'REQUEST_SYNC'
    ) {
      ws.send(
        JSON.stringify({
          type:
            'STATE_SYNC',

          payload:
            houseState,
        })
      );
    }
  });

  ws.on('close', () => {
    clientSessions.delete(
      ws
    );

    console.log(
      `Client disconnected. Total: ${clientSessions.size}`
    );

    broadcastPresence();
  });
});

// ============================================================
// TRACK STATE
// ============================================================

function startTrack(track) {
  houseState = {
    trackId:
      track.id,

    trackTitle:
      track.title,

    artistName:
      track.username,

    durationMs:
      track.durationMs,

    startedAt:
      Date.now(),

    roomSizeAtStart:
      clientSessions.size,
  };

  votes = {};

  skips =
    new Set();

  broadcast({
    type:
      'STATE_SYNC',

    payload:
      houseState,
  });

  broadcast({
    type:
      'VOTES_SYNC',

    payload:
      tallyVotes(),
  });

  broadcast({
    type:
      'SKIPS_SYNC',

    payload: {
      count: 0,

      needed:
        skipsNeeded(),
    },
  });

  console.log(
    `Now playing: ${houseState.trackTitle} by ${houseState.artistName}`
  );
}

// ============================================================
// QUEUE ADVANCE
// ============================================================

function advanceQueue() {
  if (
    queue.length === 0
  ) {
    houseState = {
      trackId: null,
      trackTitle: null,
      artistName: null,
      durationMs: 0,
      startedAt: null,
      roomSizeAtStart: 0,
    };

    votes = {};

    skips =
      new Set();

    broadcast({
      type:
        'STATE_SYNC',

      payload:
        houseState,
    });

    broadcast({
      type:
        'VOTES_SYNC',

      payload:
        tallyVotes(),
    });

    broadcast({
      type:
        'SKIPS_SYNC',

      payload: {
        count: 0,
        needed: 0,
      },
    });

    return;
  }

  const next =
    queue.shift();

  broadcast({
    type:
      'QUEUE_SYNC',

    payload:
      queue,
  });

  startTrack(next);
}

// ============================================================
// SKIP LOGIC
// ============================================================

function skipsNeeded() {
  if (
    !houseState.roomSizeAtStart
  ) {
    return 0;
  }

  return (
    Math.floor(
      houseState.roomSizeAtStart /
        2
    ) + 1
  );
}

function checkSkipThreshold() {
  if (
    !houseState.trackId
  ) {
    return;
  }

  const needed =
    skipsNeeded();

  if (
    needed > 0 &&
    skips.size >= needed
  ) {
    console.log(
      `Skip threshold reached (${skips.size}/${houseState.roomSizeAtStart})`
    );

    advanceQueue();
  }
}

// ============================================================
// VOTE LOGIC
// ============================================================

function tallyVotes() {
  const counts = {
    fire: 0,
    x: 0,
    neutral: 0,
  };

  Object.values(
    votes
  ).forEach((vote) => {
    if (
      counts[vote] !==
      undefined
    ) {
      counts[vote]++;
    }
  });

  return counts;
}

// ============================================================
// BROADCAST
// ============================================================

function broadcast(message) {
  const data =
    JSON.stringify(
      message
    );

  clientSessions.forEach(
    (sid, client) => {
      if (
        client.readyState ===
        WebSocket.OPEN
      ) {
        client.send(
          data
        );
      }
    }
  );
}

function broadcastPresence() {
  broadcast({
    type:
      'PRESENCE',

    payload: {
      count:
        clientSessions.size,
    },
  });
}

// ============================================================
// AUTO ADVANCE
// ============================================================

setInterval(() => {
  if (
    houseState.trackId &&
    houseState.startedAt &&
    houseState.durationMs
  ) {
    const elapsed =
      Date.now() -
      houseState.startedAt;

    if (
      elapsed >
      houseState.durationMs
    ) {
      console.log(
        'Track ended. Advancing queue.'
      );

      advanceQueue();
    }
  }
}, 2000);

// ============================================================
// START SERVER
// ============================================================

const PORT =
  process.env.PORT ||
  3000;

server.listen(
  PORT,
  () => {
    console.log(
      `Music House running on port ${PORT}`
    );
  }
);
