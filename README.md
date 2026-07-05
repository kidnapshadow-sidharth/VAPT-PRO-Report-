# 🛡 VAPT Pro — Enterprise VAPT Reporting Platform

> **Created by Sidharth Mittal** · Information Security, 

A full-featured Vulnerability Assessment & Penetration Testing report platform built in React. Runs entirely on your local machine — no cloud, no SaaS fees, no vendor lock-in.


<img width="1295" height="647" alt="image" src="https://github.com/user-attachments/assets/8a50d884-7fef-4180-8a4e-0526936b3f89" />


<img width="1252" height="635" alt="image" src="https://github.com/user-attachments/assets/ccae9162-3949-4fe9-8b01-d42ef4e81f0f" />


---

## 🚀 Quick Start

```bash
# 1. Create project
npx create-react-app vapt-pro && cd vapt-pro

# 2. Install dependencies
npm install recharts xlsx papaparse

# 3. Copy files
#    - VAPTPro_Final.jsx  →  src/App.js
#    - server.js          →  vapt-pro/server.js  (same level as package.json)

# 4. Terminal 1 — persistence server
node server.js

# 5. Terminal 2 — app
npm start
```

**Default login:** `super` / `super123`

**AI features (optional):** Get a free key at https://aistudio.google.com/apikey  
Paste it in `src/App.js` → `const GEMINI_API_KEY = "YOUR_KEY"`

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Browser  (localhost:3000)                         │
│                                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────┐  │
│  │ Login / RBAC│  │ Report Builder│  │ AI Assistant│  │PDF Engine│  │
│  │             │  │ Cover·Findings│  │ Gemini /   │  │ jsPDF +  │  │
│  │ user        │  │ SLA·Tracker  │  │ Claude API  │  │html2canvas│  │
│  │ admin       │  │ Compliance   │  │             │  │          │  │
│  │ superuser   │  │ Analytics    │  └─────┬──────┘  └────┬─────┘  │
│  └──────┬──────┘  └──────┬───────┘        │              │        │
│         │                │                │ HTTPS         │        │
└─────────┼────────────────┼────────────────┼──────────────┼────────┘
          │  fetch          │  fetch         ▼              ▼
          │  /api/storage   │  /api/audit  Gemini      Downloads/
          ▼                 ▼              Cloud       *.pdf *.xlsx
┌─────────────────────────────────────────────────────────────────────┐
│               Node Server  (localhost:4001)  server.js              │
│                                                                     │
│  GET/POST/DELETE  /api/storage/:key  →  db.json   (key-value store) │
│  GET/POST         /api/audit         →  audit.txt  (append-only log) │
└─────────────────────────────────────────────────────────────────────┘
```

**Fallback chain:** If `node server.js` is not running, every `store.get/set/del` call silently falls back to `window.storage` (Claude artifact) → `localStorage` (browser). Same `App.js` works in all three contexts.

---

## ✨ Feature Overview

### 📋 Report Builder
| Module | Details |
|---|---|
| Cover Page | Org, scope, type, classification, prepared by/for, doc ID, version |
| Executive Summary | Free-text + AI-generated summary, key observations, business impact |
| Scope & Assets | Asset table (name, IP, domain, env, type, method, status) + assessment phases |
| Findings Engine | Tabbed UI, CVSS v3.1, CVE/NVD auto-lookup, OWASP/CWE mapping |
| Retest Workflow | Open → In Progress → Retested → Closed with full history log |
| Evidence Manager | Drag-drop screenshots, Before Fix / After Fix / Retest stages, per-image captions |
| SLA Tracking | 7/30/60/90 day SLA by severity, overdue/remaining countdown, color-coded |
| Remediation Roadmap | Auto-generated P0→P3 priority table, editable SLA/owner/action |
| Compliance Mapping | OWASP, PCI DSS, ISO 27001, NIST CSF, CIS, RBI CSF, CERT-In, SEBI CSCRF, IRDAI |

### 🤖 AI Features (Gemini / Claude)
| Feature | Description |
|---|---|
| Full Finding Generator | Title in → description, impact, PoC, remediation, CVSS, OWASP auto-filled |
| Root Cause Generator | Identifies underlying technical root cause in 1-2 sentences |
| Attack Narrative | Management-friendly "how the attack happened" paragraph |
| Remediation Validation | Upload screenshot → AI says Fixed / Partially Fixed / Not Fixed |
| Executive Summary | Auto-drafted from all findings |
| AI Polish | One-click rewrite of any field in Technical / Management / Compliance mode |
| Enhance/Refine | After AI generates, type "make it shorter" → AI rewrites iteratively |
| CVE Lookup | Paste CVE ID → description, CVSS, CWE, references auto-populated from NVD |

### 📊 Analytics & Tracking
- VAPT Tracker Dashboard (Total/Open/Closed/Progress%, Risk Score, status breakdown chart)
- SLA Tracking Dashboard (overdue/amber/green per finding)
- Analytics tab (severity distribution, CVSS score chart)
- Scanner Import (Nessus, Nuclei, Qualys, Burp, Acunetix, OpenVAS CSV/XLSX)

### 🔐 Multi-User & Security
| Role | Permissions |
|---|---|
| `user` | View + download saved reports only |
| `admin` | Full report editing, no audit access |
| `superuser` | Everything + Password Manager + System Audit Trail |

- Credentials stored base64-encoded in `db.json`
- Append-only `audit.txt` logs every login, permission change, deletion
- Per-user report ownership (users see only their reports; superuser sees all with username badge)

### 📄 Export
- **PDF** — real binary `.pdf` via jsPDF + html2canvas, full-width capture, 7 themes
- **XLSX** — full findings register via SheetJS
- **JSON DB** — manual export/import for cross-machine backup

### 🎨 Themes
Dark Cyber · Light Pro · Red Team · Navy Ops · Green Ops · MD Report · CISO Exec  
Plus custom background / accent / text color with live preview

---

## 📁 Project Structure

```
vapt-pro/
├── server.js           # Zero-dependency Node persistence API
├── db.json             # Auto-created — key-value store
├── audit.txt           # Auto-created — append-only system audit log
└── src/
    └── App.js          # Full application (single-file React SPA)
```

---

## 🧰 Tech Stack

| Layer | Tech |
|---|---|
| Frontend | React 18, Tailwind CSS (utility classes) |
| Charts | Recharts |
| Spreadsheet | SheetJS (xlsx) |
| CSV parsing | PapaParse |
| PDF | jsPDF + html2canvas |
| AI | Google Gemini API / Anthropic Claude API |
| Backend | Node.js `http` + `fs` (zero npm dependencies) |
| Storage | `db.json` (server) → `localStorage` (fallback) |
| Audit | `audit.txt` (append-only text, pipe-delimited) |

---

## 📄 License

MIT — free for personal and commercial use. Attribution appreciated.
