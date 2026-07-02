# IIITA-Crypt — Deployment Guide

> **Architecture**: React (Vercel) → Node.js Backend (Render) → Python CP-ABE Microservice (Render) → MongoDB Atlas

---

## Prerequisites

- [ ] GitHub account with this repo pushed
- [ ] [Render](https://render.com) account (sign in with GitHub)
- [ ] [Vercel](https://vercel.com) account (sign in with GitHub)
- [ ] MongoDB Atlas cluster already running ✅

---

## Step 1 — Push to GitHub

If you haven't already:

```bash
git add .
git commit -m "chore: production deployment configuration"
git remote add origin https://github.com/YOUR_USERNAME/iiita-crypt.git
git push -u origin main
```

> The `.env`, `master.key`, and `node_modules/` are already in `.gitignore` — you're safe.

---

## Step 2 — Deploy Python Encryption Service on Render

1. Go to [render.com/dashboard](https://dashboard.render.com) → **New** → **Web Service**
2. Connect your GitHub repo
3. Configure:
   - **Name**: `iiita-crypt-encryption`
   - **Root Directory**: `services/encryption`
   - **Environment**: **Docker** (auto-detected from `Dockerfile`)
   - **Plan**: Free
4. Add **Environment Variable**:
   | Key | Value |
   |-----|-------|
   | `MSK` | *(your master secret key from `.env`)* |
5. Click **Deploy**
6. Wait for it to go live. Copy the URL: `https://iiita-crypt-encryption.onrender.com`
7. Verify: `curl https://iiita-crypt-encryption.onrender.com/health` → `{"status":"OK"}`

---

## Step 3 — Deploy Node.js Backend on Render

1. Go to Render → **New** → **Web Service**
2. Connect the same GitHub repo
3. Configure:
   - **Name**: `iiita-crypt-backend`
   - **Root Directory**: `backend`
   - **Environment**: **Node**
   - **Build Command**: `npm install`
   - **Start Command**: `node index.js`
   - **Plan**: Free
4. Add **Environment Variables**:
   | Key | Value |
   |-----|-------|
   | `MONGODB_URL` | Your Atlas connection string |
   | `JWT_SECRET` | Your JWT secret |
   | `OPENAI_API_KEY` | Your OpenAI key |
   | `GROQ_API_KEY` | Your Groq key |
   | `ENCRYPTION_SERVICE_URL` | `https://iiita-crypt-encryption.onrender.com` |
   | `FRONTEND_URL` | *(fill in after Step 4)* |
   | `NODE_ENV` | `production` |
5. Click **Deploy**
6. Verify: `curl https://iiita-crypt-backend.onrender.com/api/health`

---

## Step 4 — Deploy React Frontend on Vercel

1. Go to [vercel.com/new](https://vercel.com/new)
2. Import your GitHub repository
3. Configure:
   - **Framework Preset**: Vite (auto-detected)
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build` (default)
   - **Output Directory**: `dist` (default)
4. Add **Environment Variable**:
   | Key | Value |
   |-----|-------|
   | `VITE_API_URL` | `https://iiita-crypt-backend.onrender.com` |
5. Click **Deploy**
6. Copy your live URL: `https://iiita-crypt-XXXX.vercel.app`

---

## Step 5 — Update CORS on Backend

1. Go back to your **Render backend** service → **Environment**
2. Set `FRONTEND_URL` to your Vercel URL:
   ```
   https://iiita-crypt-XXXX.vercel.app
   ```
3. Render will auto-redeploy. Wait ~30 seconds.

---

## Step 6 — Verify End-to-End

1. Open your Vercel URL → Login page loads ✅
2. Log in as a student → Chat loads with history ✅
3. Ask "What is my CGPA?" → Gets decrypted personal data ✅
4. Ask "What's on the BH-1 mess menu?" → Gets hostel-restricted data ✅
5. Log in as Dean → Ask "List all students" → Gets full student list ✅

---

## Troubleshooting

### Cold Start Delays
Render free tier spins down after 15 minutes. The first request may take 30–60 seconds. This is expected. Upgrade to a paid plan for always-on.

### CORS Errors
- Ensure `FRONTEND_URL` in Render exactly matches your Vercel URL (no trailing slash).
- Vercel may give you multiple domain aliases — set all of them comma-separated.

### 503 from Encryption Service
- Check the Python service logs on Render.
- Ensure `MSK` env var is set in the encryption service, not just the backend.

### MongoDB Connection Errors
- Ensure your Atlas cluster IP access list includes `0.0.0.0/0` (allow all) for Render's dynamic IPs.
- Go to: Atlas → Network Access → Add IP Address → Allow Access from Anywhere.

---

## Local Development (unchanged)

```bash
# Terminal 1 — Python service
cd services/encryption
pip install -r requirements.txt
python main.py

# Terminal 2 — Node.js backend
cd backend
npm install
npm run dev   # (uses nodemon + concurrently)

# Terminal 3 — React frontend
cd frontend
npm install
npm run dev
```
