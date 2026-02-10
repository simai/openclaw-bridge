const express = require('express');
const { execFile } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';
const SMART_UPSTREAM_URL = process.env.SMART_UPSTREAM_URL || '';
const SMART_UPSTREAM_TOKEN = process.env.SMART_UPSTREAM_TOKEN || '';
const OPENCLAW_AGENT_TIMEOUT_MS = Number(process.env.OPENCLAW_AGENT_TIMEOUT_MS || 30000);
const DB_ENABLED = String(process.env.DB_ENABLED || '1') === '1';
const CONTEXT_SUMMARY_MAX_CHARS = Number(process.env.CONTEXT_SUMMARY_MAX_CHARS || 500);
const CONTEXT_FACTS_MAX_ITEMS = Number(process.env.CONTEXT_FACTS_MAX_ITEMS || 5);
const CONTEXT_FACT_VALUE_MAX_CHARS = Number(process.env.CONTEXT_FACT_VALUE_MAX_CHARS || 120);

let dbPool = null;
let dbInitAttempted = false;
async function getDbPool() {
  if (!DB_ENABLED) return null;
  if (dbPool) return dbPool;
  if (dbInitAttempted) return null;
  dbInitAttempted = true;
  try {
    const mysql = require('mysql2/promise');
    dbPool = mysql.createPool({
      host: process.env.DB_HOST || '127.0.0.1',
      port: Number(process.env.DB_PORT || 3306),
      user: process.env.DB_USER || 'b24_openclaw',
      password: process.env.DB_PASS || '',
      database: process.env.DB_NAME || 'b24_openclaw',
      waitForConnections: true,
      connectionLimit: 5,
    });
    return dbPool;
  } catch (e) {
    console.warn('[db] disabled/unavailable:', String(e?.message || e));
    return null;
  }
}

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

function fallbackReply() {
  return 'Сообщение получил. Сейчас временная ошибка обработки, попробуйте ещё раз через пару секунд.';
}

function trimTo(input, maxLen) {
  const s = String(input || '').trim();
  if (!s) return '';
  if (s.length <= maxLen) return s;
  return `${s.slice(0, Math.max(0, maxLen - 1))}…`;
}

function sanitizeFacts(rawFacts) {
  if (!Array.isArray(rawFacts)) return [];

  const byKey = new Map();
  for (const item of rawFacts) {
    const fact = {
      fact_key: trimTo(item?.fact_key || item?.key || '', 40),
      fact_value: trimTo(item?.fact_value || item?.value || '', Math.max(40, CONTEXT_FACT_VALUE_MAX_CHARS)),
      confidence: Number(item?.confidence || 0),
    };
    if (!fact.fact_key || !fact.fact_value) continue;

    const prev = byKey.get(fact.fact_key);
    if (!prev || fact.confidence >= prev.confidence) {
      byKey.set(fact.fact_key, fact);
    }
  }

  return Array.from(byKey.values())
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, Math.max(1, CONTEXT_FACTS_MAX_ITEMS));
}

function buildAugmentedMessage(payload = {}) {
  const userText = trimTo(payload.text || '', 4000);
  const summary = trimTo(payload.summary || '', Math.max(120, CONTEXT_SUMMARY_MAX_CHARS));
  const facts = sanitizeFacts(payload.facts);

  if (!summary && facts.length === 0) return userText;

  const lines = [];
  if (summary) lines.push(`Summary:\n${summary}`);
  if (facts.length) {
    lines.push('Known facts:');
    for (const f of facts) {
      const conf = Number.isFinite(f.confidence) ? ` (${f.confidence.toFixed(2)})` : '';
      lines.push(`- ${f.fact_key}: ${f.fact_value}${conf}`);
    }
  }
  lines.push(`User message:\n${userText}`);

  return lines.join('\n\n');
}

function buildSafeExpertSessionKey(agentId, sessionKey, expertId) {
  const raw = `agent:${agentId}:${sessionKey}:expert:${expertId}`;
  if (raw.length <= 64) return raw;
  const digest = crypto.createHash('sha1').update(raw).digest('hex').slice(0, 24);
  return `ag:${agentId.slice(0, 12)}:${expertId.slice(0, 12)}:${digest}`;
}

function isUnsafeToolRequest(payload = {}) {
  const text = String(payload.text || '').toLowerCase();
  return [
    'выполни команд', 'запусти команд', 'shell', 'bash', 'sh ', 'ssh',
    'ls /', 'cat /', 'rm ', 'sudo', 'systemctl', 'docker ', 'kubectl',
    'измени файл', 'отредактируй файл', 'покажи /root', 'покажи содержимое /root'
  ].some((k) => text.includes(k));
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

async function persistDbAudit(payload, sessionKey, routing, smartMode, failureClass, latencyMs, chatTypeSeen) {
  const pool = await getDbPool();
  if (!pool) return;

  const domain = String(payload?.domain || '').trim();
  if (!domain) return;
  const dialogId = String(payload?.dialogId || '').trim();
  const authorId = String(payload?.authorId || '').trim();
  const isGroup = chatTypeSeen === 'C' || chatTypeSeen === 'G' || dialogId.toLowerCase().startsWith('chat');
  const scopeType = isGroup ? 'group' : 'private';
  const scopeKey = isGroup ? (dialogId || authorId || 'unknown') : (authorId || dialogId || 'unknown');

  let conn = null;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    await conn.execute(
      'INSERT INTO tenants(domain, status) VALUES (?, "active") ON DUPLICATE KEY UPDATE updated_at=CURRENT_TIMESTAMP',
      [domain],
    );

    const [tenantRows] = await conn.execute('SELECT id FROM tenants WHERE domain=? LIMIT 1', [domain]);
    const tenantId = tenantRows?.[0]?.id;
    if (!tenantId) throw new Error('tenant not found');

    await conn.execute(
      `INSERT INTO conversations(tenant_id, scope_type, scope_key, session_key, last_message_at, last_agent_id, last_expert_id, state_json)
       VALUES(?, ?, ?, ?, NOW(), ?, ?, NULL)
       ON DUPLICATE KEY UPDATE
         last_message_at=VALUES(last_message_at),
         last_agent_id=VALUES(last_agent_id),
         last_expert_id=VALUES(last_expert_id),
         updated_at=CURRENT_TIMESTAMP`,
      [tenantId, scopeType, scopeKey, sessionKey, routing.agentId || null, routing.expertId || null],
    );

    const [convRows] = await conn.execute('SELECT id FROM conversations WHERE session_key=? LIMIT 1', [sessionKey]);
    const conversationId = convRows?.[0]?.id || null;

    await conn.execute(
      `INSERT INTO routing_audit(tenant_id, conversation_id, request_id, router_reason, expert_id, agent_id, smart_mode, failure_class, latency_ms)
       VALUES(?, ?, NULL, ?, ?, ?, ?, ?, ?)`,
      [tenantId, conversationId, routing.reason || null, routing.expertId || null, routing.agentId || null, smartMode || null, failureClass || null, latencyMs || null],
    );

    await conn.commit();
  } catch (e) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }
    console.warn('[db] audit write failed:', String(e?.message || e));
  } finally {
    if (conn) conn.release();
  }
}

async function getSmartReply(payload, sessionKey, expertId = 'general', agentId = 'bitrix-router') {
  const augmentedMessage = buildAugmentedMessage(payload);

  if (!SMART_UPSTREAM_URL) {
    // Local smart mode via OpenClaw CLI (no extra URL config required)
    try {
      const expertSessionKey = buildSafeExpertSessionKey(agentId, sessionKey, expertId);
      const { stdout } = await execFileAsync(
        'openclaw',
        [
          'agent', '--local', '--json',
          '--agent', agentId,
          '--session-id', expertSessionKey,
          '--message', augmentedMessage,
          '--timeout', String(Math.max(10, Math.ceil(OPENCLAW_AGENT_TIMEOUT_MS / 1000))),
        ],
        { timeout: OPENCLAW_AGENT_TIMEOUT_MS + 5000, maxBuffer: 20 * 1024 * 1024 },
      );
      const parsed = JSON.parse(stdout || '{}');
      const reply = String((parsed?.payloads || []).map(p => p?.text || '').filter(Boolean).join('\n')).trim();
      if (reply) return { reply, smartMode: 'openclaw-agent-local' };
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
      body: JSON.stringify({ ...payload, text: augmentedMessage, sessionKey, expertId, source: 'bitrix24-bridge' }),
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

const CHANNEL_REQUEST_ID_TTL_MS = Number(process.env.CHANNEL_REQUEST_ID_TTL_MS || 5 * 60 * 1000);
const CHANNEL_MAX_CLOCK_SKEW_SEC = Number(process.env.CHANNEL_MAX_CLOCK_SKEW_SEC || 300);
/** @type {Map<string, {ts:number, response:any}>} */
const channelIdempotency = new Map();

function cleanupChannelIdempotency(nowMs = Date.now()) {
  for (const [k, v] of channelIdempotency.entries()) {
    if (!v || (nowMs - v.ts) > CHANNEL_REQUEST_ID_TTL_MS) channelIdempotency.delete(k);
  }
}

function hmacHex(bodyText, secret) {
  return crypto.createHmac('sha256', secret).update(bodyText).digest('hex');
}

function safeEqHex(a, b) {
  const x = Buffer.from(String(a || ''), 'hex');
  const y = Buffer.from(String(b || ''), 'hex');
  if (x.length === 0 || y.length === 0 || x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

function parseSig(headerValue = '') {
  const s = String(headerValue || '').trim();
  if (!s) return '';
  if (s.startsWith('sha256=')) return s.slice('sha256='.length);
  return s;
}

function uuidish(v) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(v || '').trim());
}

function validateChannelInbound(body) {
  const requestId = String(body?.requestId || '').trim();
  const domain = String(body?.tenant?.domain || '').trim();
  const tenantChannelId = String(body?.tenant?.tenantChannelId || '').trim();
  const authorId = String(body?.message?.authorId || '').trim();
  const dialogId = String(body?.message?.dialogId || '').trim();
  const text = String(body?.message?.text || '').trim();

  if (!uuidish(requestId)) return { ok: false, code: 'INVALID_SCHEMA', message: 'requestId invalid' };
  if (!domain) return { ok: false, code: 'INVALID_SCHEMA', message: 'tenant.domain missing' };
  if (!authorId) return { ok: false, code: 'INVALID_SCHEMA', message: 'message.authorId missing' };
  if (!dialogId) return { ok: false, code: 'INVALID_SCHEMA', message: 'message.dialogId missing' };
  if (!text) return { ok: false, code: 'INVALID_SCHEMA', message: 'message.text missing' };

  return { ok: true, requestId, domain, tenantChannelId, authorId, dialogId, text };
}

app.post('/v1/channel/inbound', async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: { code: 'UNAUTHORIZED', message: 'unauthorized', retryable: false } });

  const tsHeader = Number(req.headers['x-timestamp'] || 0);
  const nowSec = Math.floor(Date.now() / 1000);
  if (!tsHeader || Math.abs(nowSec - tsHeader) > CHANNEL_MAX_CLOCK_SKEW_SEC) {
    return res.status(401).json({ ok: false, error: { code: 'CLOCK_SKEW_EXCEEDED', message: 'invalid timestamp', retryable: false } });
  }

  const rawBody = JSON.stringify(req.body || {});
  if (BRIDGE_TOKEN) {
    const got = parseSig(req.headers['x-channel-signature']);
    const exp = hmacHex(rawBody, BRIDGE_TOKEN);
    if (!safeEqHex(got, exp)) {
      return res.status(401).json({ ok: false, error: { code: 'INVALID_SIGNATURE', message: 'signature mismatch', retryable: false } });
    }
  }

  cleanupChannelIdempotency();
  const parsed = validateChannelInbound(req.body || {});
  if (!parsed.ok) {
    return res.status(400).json({ ok: false, requestId: String(req.body?.requestId || ''), error: { code: parsed.code, message: parsed.message, retryable: false } });
  }

  const cached = channelIdempotency.get(parsed.requestId);
  if (cached) return res.json(cached.response);

  // B8 stub routing: contract-ready hub ingress with explicit canary-safe error behavior.
  if (!parsed.tenantChannelId) {
    const out = {
      ok: false,
      requestId: parsed.requestId,
      error: { code: 'TENANT_NOT_MAPPED', message: 'tenantChannelId missing', retryable: false },
    };
    channelIdempotency.set(parsed.requestId, { ts: Date.now(), response: out });
    return res.status(404).json(out);
  }

  const out = {
    ok: false,
    requestId: parsed.requestId,
    error: { code: 'EDGE_UNAVAILABLE', message: 'No active edge for tenant', retryable: true },
  };
  channelIdempotency.set(parsed.requestId, { ts: Date.now(), response: out });
  return res.status(503).json(out);
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
  const t0 = Date.now();

  if (isUnsafeToolRequest(payload)) {
    const blockedRouting = { ...routing, reason: 'policy-unsafe-tool-request' };
    await persistDbAudit(payload, sessionKey, blockedRouting, 'policy-blocked', null, Date.now() - t0, chatTypeSeen);
    return res.json({
      reply: 'Отказ: выполнение серверных команд, чтение системных файлов и изменение кода из чата Bitrix запрещены политикой безопасности.',
      sessionKey,
      routedBy,
      chatTypeSeen,
      smartMode: 'policy-blocked',
      smartError: null,
      expertId: routing.expertId,
      agentId: routing.agentId,
      routerReason: 'policy-unsafe-tool-request',
      messageCount: next.count,
    });
  }

  const smart = await getSmartReply(payload, sessionKey, routing.expertId, routing.agentId);
  await persistDbAudit(payload, sessionKey, routing, smart.smartMode, smart.smartError ? 'smart_error' : null, Date.now() - t0, chatTypeSeen);

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
