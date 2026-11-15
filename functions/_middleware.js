// Password gate for the whole site (Cloudflare Pages Functions).
// The password lives only in the Cloudflare variable SITE_PASSWORD.

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const safeNext = (n) => (typeof n === "string" && n.startsWith("/") && !n.startsWith("//") && !n.startsWith("/__login") ? n : "/");
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function page(next, error) {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>Erfan × Deniz</title>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500&family=Vazirmatn:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px;
font-family:'Vazirmatn',Tahoma,sans-serif;color:#efe7d8;line-height:1.9;
background:radial-gradient(ellipse 80% 45% at 50% 0%,rgba(184,153,95,.16),transparent 70%),#0f0e12}
.box{width:100%;max-width:420px;text-align:center}
.l{direction:ltr;font-family:'Manrope',Arial,sans-serif;text-transform:uppercase;letter-spacing:.3em;color:#b8995f;font-size:.7rem}
.m{font-family:'Manrope',sans-serif;font-size:1.6rem;letter-spacing:.2em;margin:6px 0 24px;direction:ltr}.m b{color:#b8995f;font-weight:400;margin:0 .2em}
.c{border:1px solid rgba(184,153,95,.35);background:#16141a;padding:30px 22px}
h1{font-size:1.3rem;font-weight:500}p{color:#a99f8e;margin:6px 0 20px;font-size:.98rem}
input{width:100%;background:#0f0e12;color:#efe7d8;border:1px solid rgba(184,153,95,.35);padding:14px;font:inherit;font-size:1.05rem;text-align:center;outline:none;border-radius:0}
input:focus{border-color:#b8995f}
button{margin-top:16px;padding:13px 38px;border:1px solid #b8995f;background:transparent;color:#efe7d8;font:inherit;font-size:1.02rem;cursor:pointer}
button:active{background:#b8995f;color:#16120a}
.e{color:#d98b94;margin-top:14px;min-height:1.6em;font-size:.95rem}
</style></head><body><div class="box"><div class="l">Private</div><div class="m">E<b>×</b>D</div>
<form class="c" method="post" action="/__login"><h1>این سایت خصوصیه 🔒</h1><p>برای ورود، رمزی که برات فرستادم رو بنویس.</p>
<input type="password" name="password" placeholder="رمز عبور" autocomplete="current-password" autofocus required>
<input type="hidden" name="next" value="${esc(next)}">
<button type="submit">ورود</button><div class="e">${error ? "رمز اشتباهه، دوباره امتحان کن 🤍" : ""}</div></form></div></body></html>`;
}

const html = (body, status) =>
  new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" } });

export async function onRequest(context) {
  const { request, env, next } = context;
  const secret = env.SITE_PASSWORD;
  if (!secret) return html("<p dir=ltr style='font-family:sans-serif;padding:24px'>SITE_PASSWORD is not set in Cloudflare.</p>", 500);

  const url = new URL(request.url);
  const token = await hmac(secret, "ed-session-v1");

  if (url.pathname === "/__login" && request.method === "POST") {
    const form = await request.formData();
    const given = String(form.get("password") || "");
    const target = safeNext(form.get("next"));
    const ok = same(await hmac(secret, given), await hmac(secret, secret));
    if (ok) {
      return new Response(null, {
        status: 302,
        headers: { location: target, "cache-control": "no-store",
          "set-cookie": `ed_auth=${token}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax` },
      });
    }
    await new Promise((r) => setTimeout(r, 700));
    return html(page(target, true), 401);
  }

  const cookie = (request.headers.get("cookie") || "").split(/;\s*/).find((c) => c.startsWith("ed_auth="));
  if (cookie && same(cookie.slice(8), token)) return next();

  const wantsPage = request.method === "GET" && (request.headers.get("accept") || "").includes("text/html");
  if (!wantsPage) return new Response("Unauthorized", { status: 401, headers: { "cache-control": "no-store" } });
  return html(page(url.pathname === "/__login" ? "/" : url.pathname + url.search, false), 401);
}
