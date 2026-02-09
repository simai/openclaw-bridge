const express = require('express');

const app = express();
app.use(express.json({ limit: '1mb' }));

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';
const SMART_UPSTREAM_URL = process.env.SMART_UPSTREAM_URL || '';
const SMART_UPSTREAM_TOKEN = process.env.SMART_UPSTREAM_TOKEN || '';

/** @type {Map<string, {createdAt:string,lastAt:string,count:number,lastText:string}>} */
const sessionState = new Map();

function authOk(req) {
  if (!BRIDGE_TOKEN) return true;
  const h = req.headers.authorization || '';
  return h === `Bearer ${BRIDGE_TOKEN}`;
}

function buildSessionRouting(payload = {}) {
  const domain = String(payload.domain || 'unknown-domain').trim() || 'unknown-domain';
  const authorId = String(payload.authorId || '').trim();
  const dialogId = String(payload.dialogId || '').trim();
  const chatType = String(payload.chatType || '').trim().toUpperCase();
  const isGroupByDialog = dialogId.toLowerCase().startsWith('chat');

  if (chatType === 'G' || chatType === 'C' || isGroupByDialog) {
    const chatPart = dialogId || authorId || 'unknown-chat';
    return {
      sessionKey: `bitrix:${domain}:chat:${chatPart}`,
      routedBy: 'domain+dialogId',
    };
  }

  const userPart = authorId || dialogId || 'unknown-user';
  return {
    sessionKey: `bitrix:${domain}:${userPart}`,
    routedBy: 'domain+authorId',
  };
}

function fallbackReply({ domain = '', authorId = '', dialogId = '', text = '' }) {
  const clean = String(text || '').trim();
  return clean
    ? `Принял (${domain}/${authorId}/${dialogId}). Сообщение: ${clean}`
    : 'Принял 👍 Работаю над ответом.';
}

async function getSmartReply(payload, sessionKey) {
  if (!SMART_UPSTREAM_URL) {
    return { reply: fallbackReply(payload), smartMode: 'fallback-no-upstream' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (SMART_UPSTREAM_TOKEN) headers.Authorization = `Bearer ${SMART_UPSTREAM_TOKEN}`;

    const response = await fetch(SMART_UPSTREAM_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({ ...payload, sessionKey, source: 'bitrix24-bridge' }),
      signal: controller.signal,
    });

    const raw = await response.text();
    let data = null;
    try { data = JSON.parse(raw); } catch (_) {}

    if (!response.ok) {
      return {
        reply: fallbackReply(payload),
        smartMode: `fallback-upstream-http-${response.status}`,
      };
    }

    const reply = String((data && data.reply) || '').trim();
    if (!reply) {
      return { reply: fallbackReply(payload), smartMode: 'fallback-upstream-empty' };
    }

    return { reply, smartMode: 'upstream' };
  } catch (_e) {
    return { reply: fallbackReply(payload), smartMode: 'fallback-upstream-error' };
  } finally {
    clearTimeout(timer);
  }
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'openclaw-bridge', timeUtc: new Date().toISOString() });
});

app.post('/v1/inbound', async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ error: 'unauthorized' });

  const payload = req.body || {};
  const chatTypeSeen = String(payload.chatType || '').trim().toUpperCase();

  const { sessionKey, routedBy } = buildSessionRouting(payload);

  const now = new Date().toISOString();
  const prev = sessionState.get(sessionKey);
  const next = {
    createdAt: prev?.createdAt || now,
    lastAt: now,
    count: (prev?.count || 0) + 1,
    lastText: String(payload.text || '').trim(),
  };
  sessionState.set(sessionKey, next);

  const smart = await getSmartReply(payload, sessionKey);

  return res.json({
    reply: smart.reply,
    sessionKey,
    routedBy,
    chatTypeSeen,
    smartMode: smart.smartMode,
    messageCount: next.count,
  });
});

app.listen(PORT, HOST, () => {
  console.log(`openclaw-bridge listening on http://${HOST}:${PORT}`);
});
