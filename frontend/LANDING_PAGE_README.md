# SignalMesh — Landing Page

Public-facing institutional overview page for SignalMesh, a privacy-preserving cross-bank AML investigation research prototype.

Built with pure semantic HTML5, CSS3, inline SVG, and vanilla JavaScript in [`frontend/landing.html`](file:///Users/gyanprakash09/Developer/Zdatathon/frontend/landing.html).

---

## 1. Quick Start

Run the landing page locally through any static HTTP server from the repository root:

```bash
# Using Python 3:
python3 -m http.server 3000 --directory frontend
```

Then open in your browser:  
👉 **`http://127.0.0.1:3000/landing.html`**

Direct links:
- **Landing Page**: [`http://127.0.0.1:3000/landing.html`](http://127.0.0.1:3000/landing.html)
- **Demo Workspace / Dashboard**: [`http://127.0.0.1:3000/index.html`](http://127.0.0.1:3000/index.html)

---

## 2. Visual Reference & Media Assets

The landing page adapts the dark-fintech aesthetic of the reference design:
- **Canvas & Palette**: Near-black background (`#070709`), `#111116` card panels, crisp white headings, muted secondary typography (`#C5C3CE`), and precise violet accents (`#8B5CF6` / `#A78BFA`).
- **Media Motif**:
  - Video asset: `https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260912_104036_bd6924f6-3c8e-417e-8465-6d03c8c2e9e6.mp4`
  - High-resolution poster fallback: `https://d2ol7oe51mr4n9.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/82e7eb75-c65f-490a-99b5-f3d1cad54200.webp`
- **Graceful Degradation**:
  - If video loading fails or autoplay is restricted by browser policy, the high-resolution poster image is displayed seamlessly.
  - If `prefers-reduced-motion: reduce` is enabled in user system settings, video autoplay and entrance animations are disabled, and the static visual is displayed.
  - If Google Fonts cannot be fetched, system fonts (`-apple-system, BlinkMacSystemFont, Segoe UI, Roboto`) maintain clean typographic hierarchy.

---

## 3. Product Positioning & Privacy Realism

The landing page conveys institutional credibility without promotional hyperbole:
1. **Investigation Leads, Not Guilt**: A matched entity token is an anomaly lead for compliance review, not proof of financial crime.
2. **Data Minimization Boundaries**: Explicitly details that bank-local transaction rows and full graphs remain inside each institution's process, while observable session metadata (bytes, set sizes, timings) is logged to the audit ledger.
3. **Prototype Disclosures**:
   - The current prototype runs across separate operating system processes using local multiprocessing IPC queues.
   - Production mutual TLS (mTLS 1.3), independent external checkpoint publishing, and IBM LinuxONE native validation are clearly marked as **unimplemented or unverified**.
   - No fabricated client logos, fake performance statistics, or claims of "tamper-proof" or "zero-leakage" security are made.
