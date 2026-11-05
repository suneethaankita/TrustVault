# TrustVault — Deployment Guide & Production Runbook

This guide describes how to deploy TrustVault to production using free cloud hosting platforms (such as Render, Railway, or Vercel) with zero credit card requirements.

---

## 🚀 Option 1: Deploying on Render (Recommended for Express + SQLite)

Render provides free Node.js hosting with native reverse-proxy support.

### Step-by-Step Instructions:
1. **Push your repository to GitHub:**
   - Make sure your repository is private or public as required by challenge guidelines.
2. **Log into Render:**
   - Go to [render.com](https://render.com) and sign in with GitHub.
3. **Create New Web Service:**
   - Click **New +** -> **Web Service**.
   - Select your `TrustVault` repository.
4. **Configure Service Settings:**
   - **Name:** `trustvault-snovasys` (or similar)
   - **Environment:** `Node`
   - **Region:** Singapore / Frankfurt / Oregon
   - **Branch:** `main`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
5. **Environment Variables:**
   Add the following variables in the **Environment** tab:
   - `NODE_ENV`: `production`
   - `JWT_SECRET`: `trustvault-high-entropy-jwt-secret-key-2026-prod`
   - `VAULT_ENCRYPTION_KEY`: `trustvault-master-zero-trust-key-2026-prod`
6. **Click "Create Web Service":**
   - Render will build the project, run database seeding automatically, and provide your public live HTTPS URL (e.g., `https://trustvault-xxxx.onrender.com`).

---

## 🚀 Option 2: Deploying Locally (From a Clean Clone)

To test the application on any standard machine:

```bash
# 1. Clone repository
git clone <your-repository-url>
cd TrustVault

# 2. Install dependencies
npm install

# 3. Start server (automatically seeds database and demo accounts)
npm start

# 4. Open browser
http://localhost:3000
```

---

## 🧪 Post-Deployment Smoke Test Checklist

After deployment, verify the live system using an **Incognito / Private Window**:
1. Open the live URL. Verify the Evaluator Quick Access bar is visible at the top.
2. Click **Alice (Owner)**: Verify "Executive Salary Letter 2026" is listed.
3. Click **Bob (Authorized Viewer)**: Verify Bob can download the document.
4. Click **Charlie (Outsider)**: Verify Charlie sees "No Authorized Documents Found" and cannot access Alice's document.
5. Click **Security Admin**: Go to **Global Audit Trail** and click **Verify Cryptographic Integrity**. Verify that verification returns PASSED with 100% integrity.
