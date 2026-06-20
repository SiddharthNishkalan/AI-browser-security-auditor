(function () {
  const TRACKER_CATEGORIES = {
    "Google Analytics": ["google-analytics.com", "googletagmanager.com", "analytics.google.com"],
    "Advertising": ["doubleclick.net", "googlesyndication.com", "adservice.google.com", "adsystem.com"],
    "Meta Pixel": ["connect.facebook.net", "facebook.net/tr", "facebook.com/tr"],
    "Session Recording": ["hotjar.com", "fullstory.com", "mouseflow.com", "clarity.ms", "logrocket.com"],
    "Tag Manager": ["segment.com", "segment.io", "tealiumiq.com", "mathtag.com"],
    "Generic Tracker": ["track.", "/track/", "pixel.", "/pixel", "beacon", "collect?"]
  };

  const permissionEvents = new Set();
  const fingerprintEvents = new Set();
  let scanTimer = null;

  injectPageHooks();
  installFingerprintHooks();
  installPermissionHooks();
  scheduleScan(400);

  const observer = new MutationObserver(() => scheduleScan(1200));
  observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["src", "href", "style", "hidden"] });

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "SCAN_NOW") {
      scheduleScan(50);
    }
  });

  window.addEventListener("message", (message) => {
    if (message.source !== window || message.data?.channel !== "AI_SECURITY_AUDITOR_EVENT") return;
    const event = message.data.event;
    if (event?.type === "fingerprinting" && event.api) {
      recordFingerprint(event.api);
    }
    if (event?.type === "permission" && event.permission) {
      permissionEvents.add(event.permission);
      scheduleScan(100);
    }
  });

  function injectPageHooks() {
    const script = document.createElement("script");
    script.src = chrome.runtime.getURL("src/pageHooks.js");
    script.async = false;
    script.onload = () => script.remove();
    (document.documentElement || document.head).appendChild(script);
  }

  function scheduleScan(delay) {
    window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(() => {
      const scan = collectScan();
      chrome.runtime.sendMessage({ type: "PAGE_SCAN", scan }).catch(() => undefined);
    }, delay);
  }

  function collectScan() {
    const scripts = collectScripts();
    return {
      url: location.href,
      title: document.title,
      timestamp: Date.now(),
      visibleText: collectVisibleText(),
      redirectLikely: hasRedirectSignals(),
      redirectChain: collectRedirectHints(),
      forms: collectForms(),
      iframes: collectIframes(),
      scripts,
      trackers: collectTrackers(scripts),
      fingerprintingApis: collectFingerprintingSignals(scripts),
      permissionPrompts: [...permissionEvents]
    };
  }

  function collectVisibleText() {
    const text = document.body?.innerText || "";
    return text.replace(/\s+/g, " ").trim().slice(0, 4000);
  }

  function collectForms() {
    return [...document.forms].map((form) => {
      const inputs = [...form.querySelectorAll("input, textarea, select")].map((input) => {
        const type = (input.getAttribute("type") || input.tagName || "text").toLowerCase();
        return {
          type,
          name: `${input.getAttribute("name") || ""} ${input.getAttribute("id") || ""} ${input.getAttribute("autocomplete") || ""}`.toLowerCase(),
          placeholder: (input.getAttribute("placeholder") || "").toLowerCase(),
          hidden: type === "hidden" || isHidden(input)
        };
      });
      return {
        action: form.action || location.href,
        method: (form.method || "get").toLowerCase(),
        autocompleteOff: form.autocomplete === "off" || inputs.some((input) => input.name.includes("autocomplete off")),
        hidden: isHidden(form),
        inputs
      };
    });
  }

  function collectIframes() {
    return [...document.querySelectorAll("iframe")].map((frame) => ({
      src: frame.src || "",
      hidden: isHidden(frame),
      sandbox: frame.getAttribute("sandbox") || "",
      host: hostFor(frame.src)
    }));
  }

  function collectScripts() {
    return [...document.scripts].map((script) => {
      const src = script.src || "";
      const text = src ? "" : script.textContent || "";
      const host = hostFor(src);
      return {
        src,
        host,
        external: Boolean(src),
        suspiciousName: /eval|crypt|pack|proxy|inject|loader|payload|gate|visit|fingerprint/i.test(src),
        obfuscated: isObfuscated(text),
        inlineLength: text.length,
        fingerprintingHints: fingerprintHints(`${src} ${text.slice(0, 6000)}`)
      };
    });
  }

  function collectTrackers(scripts) {
    const resourceUrls = [
      ...scripts.map((script) => script.src),
      ...[...document.querySelectorAll("img[src], iframe[src], link[href]")].map((node) => node.src || node.href || "")
    ].filter(Boolean);

    const trackers = [];
    for (const resource of resourceUrls) {
      const lower = resource.toLowerCase();
      for (const [category, patterns] of Object.entries(TRACKER_CATEGORIES)) {
        if (patterns.some((pattern) => lower.includes(pattern))) {
          trackers.push({ category, url: resource, host: hostFor(resource) || "unknown" });
          break;
        }
      }
    }
    return trackers;
  }

  function collectFingerprintingSignals(scripts) {
    const signals = new Set([...fingerprintEvents]);
    for (const script of scripts) {
      for (const hint of script.fingerprintingHints) signals.add(hint);
    }
    return [...signals];
  }

  function hasRedirectSignals() {
    const params = new URLSearchParams(location.search);
    return ["redirect", "redirect_uri", "return", "return_url", "next", "url", "continue"].some((key) => params.has(key));
  }

  function collectRedirectHints() {
    const referrer = document.referrer ? [document.referrer] : [];
    const canonical = document.querySelector("link[rel='canonical']")?.href;
    return [...referrer, canonical].filter(Boolean);
  }

  function isHidden(element) {
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return element.hidden || style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0 || rect.width <= 1 || rect.height <= 1;
  }

  function isObfuscated(text) {
    if (!text || text.length < 300) return false;
    const evalLike = /(eval|Function|setTimeout|setInterval)\s*\(\s*["'`]|atob\s*\(|fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i.test(text);
    const longEncoded = /[A-Za-z0-9+/]{180,}={0,2}/.test(text);
    const compactRatio = text.replace(/\s/g, "").length / Math.max(text.length, 1);
    return evalLike || longEncoded || compactRatio > 0.93;
  }

  function fingerprintHints(text) {
    const lower = text.toLowerCase();
    const hints = [];
    if (lower.includes("canvas") && (lower.includes("todataurl") || lower.includes("getimagedata"))) hints.push("Canvas API");
    if (lower.includes("audiocontext") || lower.includes("offlineaudiocontext")) hints.push("Audio API");
    if (lower.includes("webgl") || lower.includes("getparameter")) hints.push("WebGL API");
    if (lower.includes("navigator.getbattery") || lower.includes("battery")) hints.push("Battery API");
    if (lower.includes("navigator.hardwareconcurrency") || lower.includes("navigator.deviceMemory".toLowerCase()) || lower.includes("useragentdata")) hints.push("Device information APIs");
    return hints;
  }

  function installFingerprintHooks() {
    hook(window.CanvasRenderingContext2D?.prototype, "getImageData", "Canvas API");
    hook(window.HTMLCanvasElement?.prototype, "toDataURL", "Canvas API");
    hook(window.HTMLCanvasElement?.prototype, "toBlob", "Canvas API");

    if (window.WebGLRenderingContext) {
      hook(WebGLRenderingContext.prototype, "getParameter", "WebGL API");
    }

    if (window.AudioContext) recordConstructor("Audio API", "AudioContext");
    if (window.OfflineAudioContext) recordConstructor("Audio API", "OfflineAudioContext");

    if (navigator.getBattery) {
      const original = navigator.getBattery.bind(navigator);
      try {
        navigator.getBattery = function () {
          recordFingerprint("Battery API");
          return original();
        };
      } catch {
        // Some browser objects are intentionally read-only.
      }
    }
  }

  function hook(target, method, api) {
    if (!target || typeof target[method] !== "function") return;
    const original = target[method];
    try {
      target[method] = function (...args) {
        recordFingerprint(api);
        return original.apply(this, args);
      };
    } catch {
      // Leave native behavior untouched when a property cannot be replaced.
    }
  }

  function recordConstructor(api, name) {
    const Original = window[name];
    try {
      window[name] = function (...args) {
        recordFingerprint(api);
        return new Original(...args);
      };
      window[name].prototype = Original.prototype;
    } catch {
      // Constructor replacement is best-effort.
    }
  }

  function recordFingerprint(api) {
    if (fingerprintEvents.has(api)) return;
    fingerprintEvents.add(api);
    chrome.runtime.sendMessage({ type: "SECURITY_EVENT", event: { type: "fingerprinting", api } }).catch(() => undefined);
  }

  function installPermissionHooks() {
    const descriptors = [
      ["geolocation", navigator.geolocation, "getCurrentPosition"],
      ["geolocation", navigator.geolocation, "watchPosition"],
      ["media", navigator.mediaDevices, "getUserMedia"],
      ["notifications", window.Notification, "requestPermission"],
      ["clipboard", navigator.clipboard, "readText"],
      ["clipboard", navigator.clipboard, "writeText"]
    ];
    for (const [name, target, method] of descriptors) {
      if (!target || typeof target[method] !== "function") continue;
      const original = target[method].bind(target);
      try {
        target[method] = (...args) => {
          permissionEvents.add(name);
          scheduleScan(100);
          return original(...args);
        };
      } catch {
        // Permission hooks are best-effort.
      }
    }
  }

  function hostFor(value) {
    try {
      return new URL(value, location.href).hostname;
    } catch {
      return "";
    }
  }
})();
