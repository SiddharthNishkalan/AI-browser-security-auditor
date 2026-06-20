const SCORE_RULES = {
  insecurePage: 25,
  hiddenIframe: 10,
  suspiciousLoginForm: 20,
  obfuscatedScript: 25,
  fingerprintingApi: 15,
  trackingScript: 5,
  suspiciousRedirect: 15,
  dataExfiltrationAttempt: 30,
  mixedContent: 10,
  riskyExternalScript: 12,
  brandImpersonation: 22,
  excessivePermissionPrompt: 12
};

const TRACKER_CATEGORIES = {
  "Google Analytics": ["google-analytics.com", "googletagmanager.com", "analytics.google.com"],
  "Advertising": ["doubleclick.net", "googlesyndication.com", "adservice.google.com", "adsystem.com"],
  "Meta Pixel": ["connect.facebook.net", "facebook.net/tr", "facebook.com/tr"],
  "Session Recording": ["hotjar.com", "fullstory.com", "mouseflow.com", "clarity.ms", "logrocket.com"],
  "Tag Manager": ["segment.com", "segment.io", "tealiumiq.com", "mathtag.com"],
  "Generic Tracker": ["track.", "/track/", "pixel.", "/pixel", "beacon", "collect?"]
};

const BRAND_DOMAINS = {
  google: ["google.com", "accounts.google.com"],
  microsoft: ["microsoft.com", "live.com", "office.com", "login.microsoftonline.com"],
  apple: ["apple.com", "icloud.com"],
  facebook: ["facebook.com", "meta.com"],
  amazon: ["amazon.com"],
  paypal: ["paypal.com"],
  netflix: ["netflix.com"],
  instagram: ["instagram.com"]
};

export function analyzeScan(scan, priorEvents = []) {
  const findings = [];
  const url = safeUrl(scan.url);
  const hostname = url?.hostname || "";
  const pageText = `${scan.title || ""} ${scan.visibleText || ""}`.toLowerCase();

  if (url && url.protocol !== "https:") {
    findings.push(finding("insecure-page", "Insecure connection", "high", SCORE_RULES.insecurePage, "This page is not protected by HTTPS. Data entered here may be exposed in transit.", "Avoid entering passwords, payment details, or private information."));
  }

  if (scan.redirectChain?.length > 2 || scan.redirectLikely) {
    findings.push(finding("suspicious-redirect", "Possible redirect chain", "medium", SCORE_RULES.suspiciousRedirect, "The page appears to have redirected through multiple addresses or uses redirect-style URL parameters.", "Check the address bar carefully before signing in or downloading anything."));
  }

  const hiddenIframes = scan.iframes?.filter((frame) => frame.hidden) || [];
  if (hiddenIframes.length) {
    findings.push(finding("hidden-iframe", "Hidden iframe detected", "medium", SCORE_RULES.hiddenIframe, `${hiddenIframes.length} hidden iframe${hiddenIframes.length === 1 ? "" : "s"} were found. Hidden frames can be used for tracking, clickjacking, or silent content loading.`, "Be cautious with pages that load hidden third-party content."));
  }

  const mixedContent = scan.scripts?.filter((script) => script.src?.startsWith("http://")) || [];
  if (url?.protocol === "https:" && mixedContent.length) {
    findings.push(finding("mixed-content", "Insecure script on secure page", "medium", SCORE_RULES.mixedContent, "A secure page is loading at least one script over plain HTTP.", "Do not submit sensitive details until the site fixes insecure resources."));
  }

  const riskyExternalScripts = scan.scripts?.filter((script) => script.external && !sameSite(hostname, script.host) && script.suspiciousName) || [];
  if (riskyExternalScripts.length) {
    findings.push(finding("risky-external-script", "Suspicious external script", "medium", SCORE_RULES.riskyExternalScript, `${riskyExternalScripts.length} third-party script${riskyExternalScripts.length === 1 ? "" : "s"} matched suspicious naming or loading patterns.`, "Review the site source or avoid entering private data if the page already feels unexpected."));
  }

  const obfuscated = scan.scripts?.filter((script) => script.obfuscated) || [];
  if (obfuscated.length) {
    findings.push(finding("obfuscated-script", "Obfuscated script detected", "high", SCORE_RULES.obfuscatedScript, `${obfuscated.length} script${obfuscated.length === 1 ? "" : "s"} appear minified or obfuscated in a way commonly used to hide behavior.`, "Treat downloads, pop-ups, and login prompts on this page with extra caution."));
  }

  const trackers = dedupeTrackers(scan.trackers || []);
  for (const tracker of trackers) {
    findings.push(finding(`tracker-${slug(tracker.category)}-${slug(tracker.host)}`, `${tracker.category} tracker`, "low", SCORE_RULES.trackingScript, `A third-party tracking resource from ${tracker.host} was detected.`, "Use browser privacy controls or a trusted content blocker if you want to reduce tracking."));
  }

  const fpSignals = new Set([...(scan.fingerprintingApis || []), ...priorEvents.filter((event) => event.type === "fingerprinting").map((event) => event.api)]);
  for (const api of fpSignals) {
    findings.push(finding(`fingerprinting-${slug(api)}`, `${api} fingerprinting signal`, "medium", SCORE_RULES.fingerprintingApi, `The page accessed ${api}, which can contribute to browser fingerprinting.`, "Avoid granting extra permissions and consider stricter privacy settings on unfamiliar sites."));
  }

  const loginFindings = analyzeForms(scan.forms || [], url);
  findings.push(...loginFindings);

  const brandFinding = analyzeBrandImpersonation(pageText, hostname);
  if (brandFinding) findings.push(brandFinding);

  const permissionCount = scan.permissionPrompts?.length || 0;
  if (permissionCount >= 2) {
    findings.push(finding("excessive-permissions", "Multiple permission prompts", "medium", SCORE_RULES.excessivePermissionPrompt, "The page requested several browser capabilities such as location, camera, microphone, notifications, or clipboard access.", "Only approve permissions when the request clearly matches what you are trying to do."));
  }

  const total = Math.min(100, findings.reduce((sum, item) => sum + item.score, 0));
  const severity = severityForScore(total);
  const categories = summarizeCategories(findings);

  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    url: scan.url,
    title: scan.title || hostname || "Untitled page",
    timestamp: Date.now(),
    riskScore: total,
    severity,
    categories,
    summary: buildSummary(total, severity, findings),
    recommendations: buildRecommendations(findings, total),
    findings
  };
}

export function buildLocalAssistantSummary(report) {
  if (!report.findings.length) {
    return "No clear high-risk behavior was detected during this scan. Keep using normal caution before sharing private information.";
  }

  const top = [...report.findings].sort((a, b) => b.score - a.score).slice(0, 3);
  const issueList = top.map((item) => item.title.toLowerCase()).join(", ");
  return `This page is rated ${report.severity.toLowerCase()} risk because it shows ${issueList}. Review the address bar, avoid entering sensitive information unless you trust the site, and follow the recommendations below.`;
}

export function severityForScore(score) {
  if (score >= 76) return "Critical";
  if (score >= 51) return "High";
  if (score >= 26) return "Medium";
  return "Low";
}

export function knownTrackerCategories() {
  return TRACKER_CATEGORIES;
}

function analyzeForms(forms, pageUrl) {
  const findings = [];
  const sensitiveNames = ["password", "pass", "pwd", "ssn", "card", "credit", "cvv", "otp", "token", "pin"];

  for (const form of forms) {
    const actionUrl = safeUrl(form.action, pageUrl?.href);
    const hasPassword = form.inputs?.some((input) => input.type === "password" || sensitiveNames.some((name) => input.name?.includes(name))) || false;
    const externalAction = Boolean(actionUrl && pageUrl && !sameSite(pageUrl.hostname, actionUrl.hostname));
    const insecureAction = actionUrl?.protocol === "http:";
    const hiddenSensitive = form.inputs?.some((input) => input.hidden && sensitiveNames.some((name) => input.name?.includes(name))) || false;

    if (hasPassword && (externalAction || insecureAction || form.autocompleteOff)) {
      const details = [
        externalAction ? "submits to a different domain" : "",
        insecureAction ? "uses an insecure submission address" : "",
        form.autocompleteOff ? "turns off password manager help" : ""
      ].filter(Boolean).join(", ");
      findings.push(finding("suspicious-login-form", "Suspicious login form", "high", SCORE_RULES.suspiciousLoginForm, `A credential-style form ${details}.`, "Confirm the domain is correct before entering credentials."));
    }

    if (hiddenSensitive || (hasPassword && externalAction && insecureAction)) {
      findings.push(finding("data-exfiltration-form", "Possible data leakage form", "critical", SCORE_RULES.dataExfiltrationAttempt, "A form may be collecting sensitive information in a risky way.", "Do not submit the form unless you can verify the site is legitimate."));
    }
  }

  return uniqueFindings(findings);
}

function analyzeBrandImpersonation(text, hostname) {
  for (const [brand, trustedDomains] of Object.entries(BRAND_DOMAINS)) {
    if (!text.includes(brand)) continue;
    if (trustedDomains.some((domain) => sameSite(hostname, domain))) continue;
    const looksRelated = hostname.includes(brand) || text.includes(`${brand} account`) || text.includes(`sign in with ${brand}`);
    if (looksRelated) {
      return finding("brand-impersonation", "Possible brand impersonation", "high", SCORE_RULES.brandImpersonation, `The page references ${brand} sign-in or account language but is not on a known ${brand} domain.`, "Open the service directly from a saved bookmark or by typing its address yourself.");
    }
  }
  return null;
}

function buildSummary(score, severity, findings) {
  if (!findings.length) return "No notable risks were detected in the current scan.";
  return `${findings.length} finding${findings.length === 1 ? "" : "s"} produced a ${severity.toLowerCase()} risk score of ${score}.`;
}

function buildRecommendations(findings, score) {
  const recommendations = new Set();
  if (score >= 51) recommendations.add("Avoid entering passwords, payment details, or identity information on this page.");
  if (findings.some((item) => item.id.includes("brand-impersonation") || item.id.includes("login"))) recommendations.add("Verify the domain manually before signing in.");
  if (findings.some((item) => item.id.includes("tracker"))) recommendations.add("Consider browser privacy controls or a trusted blocker to reduce tracking.");
  if (findings.some((item) => item.id.includes("fingerprinting"))) recommendations.add("Limit permissions and use stricter privacy settings on unfamiliar sites.");
  if (findings.some((item) => item.id.includes("insecure") || item.id.includes("mixed"))) recommendations.add("Prefer the HTTPS version of the site when available.");
  if (!recommendations.size) recommendations.add("Continue browsing with normal caution.");
  return [...recommendations];
}

function summarizeCategories(findings) {
  return {
    phishing: findings.filter((item) => item.id.includes("login") || item.id.includes("brand")).length,
    privacy: findings.filter((item) => item.id.includes("tracker") || item.id.includes("fingerprinting")).length,
    malware: findings.filter((item) => item.id.includes("obfuscated") || item.id.includes("iframe") || item.id.includes("script")).length,
    dataLeakage: findings.filter((item) => item.id.includes("exfiltration") || item.id.includes("insecure")).length
  };
}

function finding(id, title, severity, score, description, recommendation) {
  return { id, title, severity, score, description, recommendation };
}

function dedupeTrackers(trackers) {
  const seen = new Set();
  return trackers.filter((tracker) => {
    const key = `${tracker.category}-${tracker.host}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function uniqueFindings(findings) {
  const seen = new Set();
  return findings.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

function safeUrl(value, base) {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

function sameSite(leftHost = "", rightHost = "") {
  const left = baseDomain(leftHost);
  const right = baseDomain(rightHost);
  return Boolean(left && right && (left === right || leftHost.endsWith(`.${right}`) || rightHost.endsWith(`.${left}`)));
}

function baseDomain(host = "") {
  const cleaned = host.replace(/^www\./, "").toLowerCase();
  const parts = cleaned.split(".").filter(Boolean);
  if (parts.length <= 2) return cleaned;
  return parts.slice(-2).join(".");
}

function slug(value = "") {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "unknown";
}
