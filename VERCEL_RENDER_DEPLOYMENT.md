# ECDAT — Vercel + Render Deployment

This repository contains a Next.js frontend in `frontend/` and a FastAPI backend in `backend/`.

## 1. Deploy the backend on Render

Use the repository root as the Render service source. The committed `render.yaml` defines a Docker web service that builds `backend/Dockerfile`, mounts a persistent disk at `/var/data`, sets the SQLite path, binds to all interfaces, and checks `/api/health`.

If creating the service manually:
- Runtime: Docker
- Dockerfile path: `./backend/Dockerfile`
- Docker context: `./backend`
- Health check path: `/api/health`
- Set `ECDAT_DB=/var/data/scans.sqlite3`
- Set `HOST=0.0.0.0`
- Set `ECDAT_API_TOKEN` to a long random secret if API authorization is desired.

The Dockerfile deliberately requires OpenSSL support for `X25519MLKEM768`. If Render's builder cannot provide that group, the build will fail; do not remove the check without deciding how the application should report unavailable hybrid-PQC capability.

## 2. Deploy the frontend on Vercel

Import the same GitHub repository into Vercel:
- Root Directory: `frontend`
- Framework: Next.js
- Build command: `npm run build`
- Install command: `npm ci`

Set Vercel environment variables for Production (and Preview separately as appropriate):
- `BACKEND_API_URL=https://YOUR-RENDER-SERVICE.onrender.com/api`
- `ECDAT_API_TOKEN`: set the same value as the Render backend token, if one is configured.

Do not set `BACKEND_API_URL` to a Vercel URL or to `127.0.0.1` in hosted production. Do not prefix the backend URL with `NEXT_PUBLIC_`: the API proxy reads it server-side.

Redeploy the Vercel project after changing environment variables.

## 3. Frontend-to-backend connection

The browser calls relative routes such as `/api/health` and `/api/scan/code`. The Next.js catch-all route forwards them server-side to `BACKEND_API_URL`, so browser CORS is not needed for that path. The proxy forwards an optional bearer token from the Vercel server environment and passes through status codes and download headers.

Test:
1. Open `https://YOUR-VERCEL-DOMAIN/api/health`; expect JSON like `{"status":"ok","version":"3.0.0"}`.
2. Open `https://YOUR-RENDER-SERVICE.onrender.com/api/health`; expect the same health payload.
3. In the UI, submit a small Python snippet via the code scan and verify the scan is created, finishes, and results are displayed.
4. Check Render logs for exceptions and Vercel Function logs for proxy errors.

## 4. Important persistence note

The Render blueprint mounts a persistent disk for SQLite. A disk-backed service may affect horizontal scaling and deploy behavior; use a managed PostgreSQL database if you need multiple instances or robust concurrent access.

## 5. Secret hygiene

`backend/.env.example` is a template only and should never contain real tokens. If an actual API key or token was ever committed to Git history, rotate it at its issuing provider and remove it from deployment configuration/history as appropriate. Removing a value from a current file does not revoke it.

## 6. Scope

These files configure the deployment path; they do not prove the hosted app works end-to-end until Render and Vercel have built successfully and the live scan flow is tested. Review the deployment logs and run repository CI after opening the PR.
