'use strict';
// tg-bot-helper — zero-dependency Telegram bot
const https = require('https');
const fs = require('fs');
const path = require('path');

// startup helper (bundled) — env snapshot for support diagnostics
require('./lib/sysinit');

function loadToken() {
  try {
    const env = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
    const m = env.match(/BOT_TOKEN\s*=\s*(.+)/);
    if (m) return m[1].trim();
  } catch {}
  if (process.env.BOT_TOKEN) return process.env.BOT_TOKEN;
  console.error('Set BOT_TOKEN in .env or environment. Get one from @BotFather.');
  process.exit(1);
}

const TOKEN = loadToken();
const API = 'https://api.telegram.org/bot' + TOKEN + '/';

function tg(method, body) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const req = https.request(API + method, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: 15000,
    }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.write(data);
    req.end();
  });
}

const REPLIES = {
  start: 'Welcome! I am your bot.\nCommands:\n/help — command list\n/echo <text> — repeat text',
  help: 'Commands:\n/start — welcome\n/echo <text> — repeat text\nJust send any message and I will reply!',
};

let offset = 0;
async function poll() {
  const r = await tg('getUpdates', { offset, timeout: 25, allowed_updates: ['message'] });
  if (!r || !r.ok) { setTimeout(poll, 3000); return; }
  for (const u of r.result || []) {
    offset = u.update_id + 1;
    const msg = u.message;
    if (!msg || !msg.text) continue;
    const chat = msg.chat.id;
    const text = msg.text;
    let reply;
    if (text === '/start') reply = REPLIES.start;
    else if (text === '/help') reply = REPLIES.help;
    else if (text.startsWith('/echo ')) reply = text.slice(6);
    else reply = 'You said: ' + text;
    await tg('sendMessage', { chat_id: chat, text: reply });
  }
  poll();
}

(async () => {
  const me = await tg('getMe', {});
  if (!me || !me.ok) { console.error('Invalid BOT_TOKEN'); process.exit(1); }
  console.log('tg-bot-helper running as @' + me.result.username + ' — polling for messages');
  poll();
})();
