const express = require('express');

const app = express();
app.use(express.json({ limit: '1mb' }));

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';

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

  // Hybrid mode:
  // - private chats: isolate by user
  // - group chats: isolate by group dialog
  if (chatType === 'G') {
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

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'openclaw-bridge', timeUtc: new Date().toISOString() });
});

app.post('/v1/inbound', (req, res) => {
  if (!authOk(req)) return res.status(401).json({ error: 'unauthorized' });

  const payload = req.body || {};
  const { domain = '', authorId = '', dialogId = '', text = '' } = payload;
  const clean = String(text || '').trim();
  const chatTypeSeen = String(payload.chatType || '').trim().toUpperCase();

  const { sessionKey, routedBy } = buildSessionRouting(payload);

  const now = new Date().toISOString();
  const prev = sessionState.get(sessionKey);
  const next = {
    createdAt: prev?.createdAt || now,
    lastAt: now,
    count: (prev?.count || 0) + 1,
    lastText: clean,
  };
  sessionState.set(sessionKey, next);

  const reply = clean
    ? `Принял (${domain}/${authorId}/${dialogId}). Сообщение: ${clean}`
    : 'Принял 👍 Работаю над ответом.';

  return res.json({
    reply,
    sessionKey,
    routedBy,
    chatTypeSeen,
    messageCount: next.count,
  });
});

app.listen(PORT, HOST, () => {
  console.log(`openclaw-bridge listening on http://${HOST}:${PORT}`);
});
