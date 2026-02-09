const express = require('express');
const { execFile } = require('child_process');
const { promisify } = require('util');

const app = express();
app.use(express.json({ limit: '1mb' }));

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';
const SMART_UPSTREAM_URL = process.env.SMART_UPSTREAM_URL || '';
const SMART_UPSTREAM_TOKEN = process.env.SMART_UPSTREAM_TOKEN || '';
const OPENCLAW_AGENT_TIMEOUT_MS = Number(process.env.OPENCLAW_AGENT_TIMEOUT_MS || 30000);

/** @type {Map<string, {createdAt:string,lastAt:string,count:number,lastText:string}>} */
const sessionState = new Map();
const execFileAsync = promisify(execFile);

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

function selectExpert(payload = {}) {
  const text = String(payload.text || '').toLowerCase();
  const hasAny = (arr) => arr.some((w) => text.includes(w));

  if (hasAny(['ошибк', 'не работает', 'баг', 'problem', 'support', 'помоги'])) {
    return { expertId: 'support', agentId: 'bitrix-support', reason: 'support-keywords' };
  }
  if (hasAny(['цена', 'тариф', 'купить', 'оплат', 'коммерч', 'sales'])) {
    return { expertId: 'sales', agentId: 'bitrix-sales', reason: 'sales-keywords' };
  }
  if (hasAny(['процесс', 'регламент', 'операц', 'внедрен', 'интеграц', 'деплой', 'разверт'])) {
    return { expertId: 'ops', agentId: 'bitrix-ops', reason: 'ops-keywords' };
  }

  return { expertId: 'general', agentId: 'bitrix-router', reason: 'default-general' };
}

async function getSmartReply(payload, sessionKey, expertId = 'general', agentId = 'bitrix-router') {
  if (!SMART_UPSTREAM_URL) {
    // Local smart mode via OpenClaw CLI (no extra URL config required)
    try {
      const expertSessionKey = `agent:${agentId}:${sessionKey}:expert:${expertId}`;
      const params = JSON.stringify({
        idempotencyKey: `b24-${Date.now()}`,
        agentId,
        sessionKey: expertSessionKey,
        message: String(payload.text || '').trim(),
      });
      const { stdout } = await execFileAsync(
        'openclaw',
        ['gateway', 'call', 'agent', '--json', '--expect-final', '--timeout', String(OPENCLAW_AGENT_TIMEOUT_MS), '--params', params],
        { timeout: OPENCLAW_AGENT_TIMEOUT_MS + 3000, maxBuffer: 20 * 1024 * 1024 },
      );
      const parsed = JSON.parse(stdout || '{}');
      const reply = String((parsed?.result?.payloads || []).map(p => p?.text || '').filter(Boolean).join('\n')).trim();
      if (reply) return { reply, smartMode: 'openclaw-cli' };
      return { reply: fallbackReply(payload), smartMode: 'fallback-openclaw-empty' };
    } catch (e) {
      return { reply: fallbackReply(payload), smartMode: 'fallback-openclaw-error', smartError: String(e?.message || e) };
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (SMART_UPSTREAM_TOKEN) headers.Authorization = `Bearer ${SMART_UPSTREAM_TOKEN}`;

    const response = await fetch(SMART_UPSTREAM_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({ ...payload, sessionKey, expertId, source: 'bitrix24-bridge' }),
      signal: controller.signal,
    });

    const raw = await response.text();
    let data = null;
    try { data = JSON.parse(raw); } catch (_) {}

    if (!response.ok) {
      return { reply: fallbackReply(payload), smartMode: `fallback-upstream-http-${response.status}` };
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

  const routing = selectExpert(payload);
  const smart = await getSmartReply(payload, sessionKey, routing.expertId, routing.agentId);

  return res.json({
    reply: smart.reply,
    sessionKey,
    routedBy,
    chatTypeSeen,
    smartMode: smart.smartMode,
    smartError: smart.smartError || null,
    expertId: routing.expertId,
    agentId: routing.agentId,
    routerReason: routing.reason,
    messageCount: next.count,
  });
});

app.listen(PORT, HOST, () => {
  console.log(`openclaw-bridge listening on http://${HOST}:${PORT}`);
});
