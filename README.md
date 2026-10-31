# Cipher Browser (Prism proxy)

Zero dependencies. Needs Node 20+.

## Run it on your computer
    node server.js
Then open http://localhost:3000

## Put it online with Render (free)
1. Push this folder to a new GitHub repo.
2. On render.com: New + > Web Service > pick the repo.
3. Runtime: Node. Build command: (leave empty). Start command: `node server.js`.
4. Click Create. Render gives you a URL.

## Limits (be honest with yourself)
- Rewrites links on the server, so it's great for simple/static sites.
- Not a service-worker proxy: big JS apps (Instagram, YouTube, Discord) will break.
- Cookies are kept on the server per visitor (about 24h idle), so simple logins can stick. Big JS apps still break.
