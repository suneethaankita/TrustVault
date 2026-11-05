# TrustVault — Environment Variables Reference

This document explains every configuration variable used across TrustVault environments (development, staging, and production).

---

## 🔑 Variables Specification

| Variable Name | Required | Default Value | Description | Security Constraints |
| :--- | :--- | :--- | :--- | :--- |
| `PORT` | Optional | `3000` | Port on which Express HTTP server listens. | In cloud platforms (Render, Railway), this is assigned dynamically by `$PORT`. |
| `NODE_ENV` | Optional | `development` | Runtime environment mode (`development`, `production`). | When set to `production`, cookies are flagged `Secure` (HTTPS only). |
| `JWT_SECRET` | **Required in Prod** | `trustvault-super-secure-key-2026-snovasys` | HMAC SHA-256 secret key used for signing session JWTs. | Must be high-entropy, random, and at least 256 bits (32 characters). |
| `VAULT_ENCRYPTION_KEY` | **Required in Prod** | `trustvault-master-zero-trust-key-2026-snovasys` | Key derivation input for AES-256-GCM file encryption at rest. | Stored in memory only. Never logged or written to client code. |
| `DB_PATH` | Optional | `./trustvault.db` | Absolute or relative filesystem path to the SQLite database. | Must reside in a persistent directory with read/write permissions. |

---

## 🛡️ Production Secret Management Rules

1. **Zero Secret Leakage:** Never commit `.env` files into Git. The repository includes `.env.example` with harmless placeholders.
2. **Reverse Proxy Configuration:** TrustVault uses `app.set('trust proxy', 1)` so reverse proxies like Render/Cloudflare correctly supply client IP addresses for rate limiting and audit logs without exposing internal proxy headers.
