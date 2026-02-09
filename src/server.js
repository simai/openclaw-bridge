const express = require('express');

const app = express();
app.use(express.json({ limit: '1mb' }));

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';

function authOk(req) {
  if (!BRIDGE_TOKEN) return true;
  const h = req.headers.authorization || '';
  return h === `Bearer ${BRIDGE_TOKEN}`;
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'openclaw-bridge', timeUtc: new Date().toISOString() });
});

app.post('/v1/inbound', (req, res) => {
  if (!authOk(req)) return res.status(401).json({ error: 'unauthorized' });

  const { domain = '', authorId = '', dialogId = '', text = '' } = req.body || {};
  const clean = String(text || '').trim();

  const reply = clean
    ? `Принял (${domain}/${authorId}/${dialogId}). Сообщение: ${clean}`
    : 'Принял 👍 Работаю над ответом.';

  return res.json({ reply });
});

app.listen(PORT, HOST, () => {
  console.log(`openclaw-bridge listening on http://${HOST}:${PORT}`);
});
