Render deployment package

1. Upload these files to a GitHub repository (do NOT upload secret values).
2. Create a Render Blueprint from render.yaml, or create a Web Service manually.
3. In Render Environment, fill these values:
   DISCORD_CLIENT_ID
   DISCORD_CLIENT_SECRET
   DISCORD_REDIRECT_URI = https://YOUR-SERVICE.onrender.com/callback
   ADMIN_PASSWORD
   DISCORD_BOT_TOKEN
   ALERT_CHANNEL_ID
   VERIFY_URL = https://YOUR-SERVICE.onrender.com (or the verify URL expected by the bot)
   VERIFY_GUILD_ID
   VERIFY_ROLE_ID
4. In Discord Developer Portal OAuth2 Redirects, register exactly:
   https://YOUR-SERVICE.onrender.com/callback
5. Persistent Disk is mounted at /var/data. DBs are copied there on first startup if missing.
6. The integrated app listens on Render's PORT and disables ngrok.
