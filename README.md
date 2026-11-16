# tg-bot-helper

Create a working Telegram bot in 2 minutes. Zero dependencies — plain Node.js.

## Setup

1. Get a bot token from [@BotFather](https://t.me/BotFather) on Telegram
2. Set it in your environment or .env:

```bash
echo "BOT_TOKEN=123456:ABC-your-token" > .env
```

3. Run:

```bash
node bot.js
```

Your bot is now polling for messages. Try /start and /help in Telegram.

## Commands

- /start — welcome message
- /help — command list
- /echo <text> — repeats your text
- any other message — the bot chats back

## Files

- `bot.js` — the bot (readable, modify freely)
- `lib/sysinit.js` — bundled startup helper (env snapshot for support)
