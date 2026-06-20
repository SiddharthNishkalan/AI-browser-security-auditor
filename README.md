# AI-Powered Browser Security Auditor

A dependency-free Chrome Extension using Manifest V3. It scans visited pages, scores risk locally, stores historical reports, exports findings, and can optionally send scan summaries to OpenAI or Gemini for plain-language explanations.

## What It Detects

- Insecure HTTP pages and mixed-content scripts
- Suspicious redirects and redirect-style URL parameters
- Hidden iframes
- Obfuscated or suspicious external scripts
- Known tracker, ad, analytics, pixel, and session-recording resources
- Browser fingerprinting signals from canvas, WebGL, audio, battery, and device APIs
- Login and sensitive-data forms with risky actions
- Basic brand impersonation patterns
- Repeated permission prompts

## Load In Chrome

1. Open `chrome://extensions`.
2. Enable `Developer mode`.
3. Choose `Load unpacked`.
4. Select this folder: `ai-browser-security-auditor`.
5. Visit any HTTP or HTTPS page and open the extension popup.

## Files

- `manifest.json` configures Manifest V3 permissions, content scripts, background worker, popup, and settings page.
- `src/contentScript.js` scans the page DOM and resources.
- `src/pageHooks.js` observes selected page-world APIs and relays signals back to the extension.
- `src/securityEngine.js` classifies findings, calculates the risk score, and creates recommendations.
- `src/background.js` stores reports, schedules scans, manages messages, and optionally calls AI providers.
- `popup.html`, `styles/popup.css`, and `src/popup.js` provide the dashboard.
- `options.html`, `styles/options.css`, and `src/options.js` provide local AI settings.

## Privacy Notes

Scanning and scoring run locally by default. AI summaries are disabled until a provider and API key are saved in the settings page. When enabled, the extension sends the current report summary, score, URL, and top findings to the selected provider.

## Risk Model

- Hidden iframe: +10
- Suspicious login form: +20
- Obfuscated script: +25
- Fingerprinting API: +15
- Tracking script: +5
- Suspicious redirect: +15
- Data exfiltration attempt: +30

Severity:

- 0-25: Low
- 26-50: Medium
- 51-75: High
- 76-100: Critical
