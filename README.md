# Roblox Cookie Checker

This project is a cookie checker for Roblox accounts with a web UI and API endpoints.

Important notes before deploying:

- Do NOT rely on file-based storage (`data/`) in serverless environments like Vercel. Use MongoDB Atlas or another persistent DB and set `MONGODB_URI`.
- Secrets and admin password must be provided via environment variables in production.

Environment variables

- `MONGODB_URI` - MongoDB connection string (optional, recommended for production)
- `DB_NAME` - Mongo database name (default: `robin_cookie_checker`)
- `SECRET_KEY` - JWT secret used to sign tokens
- `ADMIN_PASSWORD` - initial admin password (use env var instead of hardcoded default)
- `COOKIE_CHECKER_DATA_DIR` - (optional) local data folder for fallback storage during local development

Run locally

1. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

2. Run the server:

```powershell
python server.py
```

3. Open `http://localhost:8000/index.html` in your browser.

Deployment notes

- For persistent data in production, create a MongoDB Atlas cluster and set `MONGODB_URI` in your hosting provider's environment variables.
- Vercel serverless functions have ephemeral filesystems; to deploy on Vercel you should convert the API to a proper web framework (Flask/FastAPI) or use an alternative hosting (Render, Railway, VPS) that runs `server.py`.

Security

- Change `SECRET_KEY` and `ADMIN_PASSWORD` before public deployment.
- Consider tightening CORS and removing `verify=False` in requests where possible.
