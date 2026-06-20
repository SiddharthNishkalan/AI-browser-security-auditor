(function () {
  const channel = "AI_SECURITY_AUDITOR_EVENT";
  const seen = new Set();

  hook(window.CanvasRenderingContext2D?.prototype, "getImageData", "fingerprinting", "Canvas API");
  hook(window.HTMLCanvasElement?.prototype, "toDataURL", "fingerprinting", "Canvas API");
  hook(window.HTMLCanvasElement?.prototype, "toBlob", "fingerprinting", "Canvas API");

  if (window.WebGLRenderingContext) {
    hook(WebGLRenderingContext.prototype, "getParameter", "fingerprinting", "WebGL API");
  }

  wrapConstructor("AudioContext", "fingerprinting", "Audio API");
  wrapConstructor("OfflineAudioContext", "fingerprinting", "Audio API");

  if (navigator.getBattery) {
    const original = navigator.getBattery.bind(navigator);
    try {
      navigator.getBattery = function (...args) {
        emit("fingerprinting", "Battery API");
        return original(...args);
      };
    } catch {
      // Some browser objects are intentionally read-only.
    }
  }

  hook(navigator.geolocation, "getCurrentPosition", "permission", "geolocation");
  hook(navigator.geolocation, "watchPosition", "permission", "geolocation");
  hook(navigator.mediaDevices, "getUserMedia", "permission", "media");
  hook(window.Notification, "requestPermission", "permission", "notifications");
  hook(navigator.clipboard, "readText", "permission", "clipboard");
  hook(navigator.clipboard, "writeText", "permission", "clipboard");

  function hook(target, method, type, name) {
    if (!target || typeof target[method] !== "function") return;
    const original = target[method];
    try {
      target[method] = function (...args) {
        emit(type, name);
        return original.apply(this, args);
      };
    } catch {
      // Leave native behavior untouched when a property cannot be replaced.
    }
  }

  function wrapConstructor(name, type, apiName) {
    const Original = window[name];
    if (typeof Original !== "function") return;
    try {
      window[name] = function (...args) {
        emit(type, apiName);
        return new Original(...args);
      };
      window[name].prototype = Original.prototype;
    } catch {
      // Constructor replacement is best-effort.
    }
  }

  function emit(type, name) {
    const key = `${type}:${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    window.postMessage({ channel, event: { type, api: type === "fingerprinting" ? name : undefined, permission: type === "permission" ? name : undefined } }, "*");
  }
})();
