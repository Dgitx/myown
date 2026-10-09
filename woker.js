// All-in-one Cloudflare Worker: serves the player page, playlist, TV guide and icon from ONE address,
// with server-side protection. Optional settings (Worker > Settings > Variables and Secrets):
//   SITE_USER + SITE_PASS  secrets: require a login (HTTP Basic) before anything is served
//   PLAYLIST_URL, EPG_URL  secrets: keep the real upstream addresses out of this code
const UPSTREAM = "https://tivimate.viulk.xyz/channels.m3u";
const EPG_UPSTREAM = "https://tivi.viulk.xyz/metadata/epg.xml";
const ICON_UPSTREAM = "https://pictureurl.com/api/storage/file?key=u%2Fanon%2Fcaf39e63-66cb-416d-be0e-e8be46f8361f-4600333.png";
const BUILD = "27efdf851146";

const SECURITY = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Content-Security-Policy": "frame-ancestors 'none'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet"
};

// Test run only: shows in the browser console as "[Report Only] Refused to...", blocks nothing.
const STRICT_REPORT = "default-src 'none'; script-src 'self' 'unsafe-inline' https://content.jwplatform.com https://*.jwpcdn.com https://*.jwplayer.com https://*.jwplatform.com; style-src 'self' 'unsafe-inline' https://*.jwpcdn.com https://*.jwplatform.com; img-src https: data: blob:; media-src https: blob:; connect-src 'self' https:; worker-src blob:; font-src https: data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function safeEqual(a, b) {
  let r = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return r === 0;
}
function authorized(request, env) {
  if (!env.SITE_USER || !env.SITE_PASS) return true;
  const h = request.headers.get("Authorization") || "";
  if (h.slice(0, 6) !== "Basic ") return false;
  let given; try { given = atob(h.slice(6)); } catch (e) { return false; }
  return safeEqual(given, env.SITE_USER + ":" + env.SITE_PASS);
}
// Data routes only answer our own page's requests, not a browser tab opened on the address or another website.
function fromOurPage(request) {
  const site = request.headers.get("Sec-Fetch-Site"), dest = request.headers.get("Sec-Fetch-Dest");
  if (!site) return true;   // older browsers and scripts send no such header (it can be forged anyway)
  return site === "same-origin" && dest !== "document";
}

// Simple abuse limits kept in this location's memory (a speed bump, not a wall: other locations and restarts start fresh).
const hits = new Map();   // key -> { n, reset }
function bump(key, windowMs) {
  const now = Date.now(); let h = hits.get(key);
  if (!h || now > h.reset) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
  h.n++;
  if (hits.size > 5000) for (const [k, v] of hits) if (now > v.reset) hits.delete(k);
  return h;
}
function waitFor(h) { return Math.max(1, Math.ceil((h.reset - Date.now()) / 1000)); }
function lockedFor(key, max) { const h = hits.get(key); return h && Date.now() < h.reset && h.n >= max ? waitFor(h) : 0; }
function hit(key, max, windowMs) { const h = bump(key, windowMs); return h.n > max ? waitFor(h) : 0; }
function tooMany(sec) {
  return new Response("Too many requests. Try again in " + sec + " seconds.", { status: 429,
    headers: { ...SECURITY, "Retry-After": String(sec), "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" } });
}

// Short-lived signed token: the page gets one per load, and /app.js refuses requests without a fresh one.
// Optional secret TOKEN_SECRET makes the tokens unforgeable; without it a built-in value is used.
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}
const secretOf = env => env.TOKEN_SECRET || env.SITE_PASS || ("k-" + BUILD);
async function makeToken(env) { const n = Math.floor(Date.now() / 1000); return n + "." + await hmac(secretOf(env), "app:" + n); }
async function tokenOk(tok, env) {
  const parts = String(tok || "").split("."), n = Number(parts[0]);
  if (!n || !parts[1] || Math.abs(Date.now() / 1000 - n) > 120) return false;
  return safeEqual(parts[1], await hmac(secretOf(env), "app:" + n));
}

async function relay(upstream, type, ttl, priv) {
  let up;
  try { up = await fetch(upstream, { cf: { cacheTtl: ttl, cacheEverything: true } }); }
  catch (e) { return new Response("Could not reach the upstream server", { status: 502 }); }
  if (!up.ok) return new Response("Upstream answered " + up.status, { status: 502 });
  return new Response(up.body, { status: 200, headers: { ...SECURITY,
    "Content-Type": type || up.headers.get("Content-Type") || "application/octet-stream",
    "Cache-Control": priv ? "private, no-store" : "public, max-age=" + ttl } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (request.method !== "GET" && request.method !== "HEAD") return new Response("Method not allowed", { status: 405 });
    if (url.pathname === "/robots.txt") return new Response("User-agent: *\nDisallow: /\n", { headers: { "Content-Type": "text/plain" } });

    const locked = lockedFor("fail:" + ip, 5);          // 5 wrong passwords in 10 minutes = locked out for the rest of the window
    if (locked) return tooMany(locked);
    if (!authorized(request, env)) {
      if (request.headers.get("Authorization")) bump("fail:" + ip, 10 * 60e3);
      return new Response("Login required", { status: 401, headers: { ...SECURITY, "WWW-Authenticate": 'Basic realm="Private", charset="UTF-8"', "Cache-Control": "no-store" } });
    }
    if (request.headers.get("Authorization")) hits.delete("fail:" + ip);

    if (url.pathname === "/playlist" || url.pathname === "/epg") {
      const slow = hit("data:" + ip, 60, 60e3); if (slow) return tooMany(slow);   // more than 60 data requests a minute is not a viewer
      if (!fromOurPage(request)) return new Response("Not available here", { status: 403, headers: SECURITY });
      return url.pathname === "/playlist"
        ? relay(env.PLAYLIST_URL || UPSTREAM, "text/plain; charset=utf-8", 300, true)
        : relay(env.EPG_URL || EPG_UPSTREAM, "application/xml; charset=utf-8", 600, true);
    }
    if (url.pathname === "/icon.png") return relay(ICON_UPSTREAM, null, 86400, false);
    if (url.pathname === "/app.js") {
      const slowJs = hit("data:" + ip, 60, 60e3); if (slowJs) return tooMany(slowJs);
      const dest = request.headers.get("Sec-Fetch-Dest");
      if ((dest && dest !== "script") || !(await tokenOk(url.searchParams.get("t"), env)))
        return new Response("Not available here", { status: 403, headers: SECURITY });   // opening it in a tab or from view-source fails
      return new Response(APPJS, { headers: { ...SECURITY, "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-store" } });
    }
    if (url.pathname === "/version")
      return new Response(BUILD, { headers: { ...SECURITY, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });

    if (url.pathname === "/" || url.pathname === "/index.html")
      return new Response(SHELL.replace("@@T@@", await makeToken(env)), { headers: { ...SECURITY, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
        "Content-Security-Policy-Report-Only": STRICT_REPORT } });

    return new Response("Not found", { status: 404, headers: SECURITY });
  }
};
