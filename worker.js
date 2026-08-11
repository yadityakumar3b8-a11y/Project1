// Calcined Lime Fleet Tracker — Cloudflare Worker
// Serves the static app from /public for normal requests, and handles
// /api/* for auth + D1-backed CRUD. Login credentials (username/salt/password hash)
// live in the D1 `users` table, not as Worker secrets — reset your password any time
// from inside the app (Settings -> Change password). SESSION_SECRET is the only
// remaining Worker secret, set once in the Cloudflare dashboard (Settings -> Variables and Secrets).

const SESSION_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 180; // 180 days — persistent login

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        return json({ error: String((err && err.message) || err) }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};

async function handleApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;

  if (path === "/api/login" && method === "POST") {
    const body = await request.json();
    const username = (body.username || "").trim();
    const password = body.password || "";
    if (!username || !password) {
      return json({ error: "Invalid username or password" }, 401);
    }
    const row = await env.DB.prepare("SELECT username, salt, password_hash FROM users WHERE username = ?")
      .bind(username).first();
    if (!row) {
      return json({ error: "Invalid username or password" }, 401);
    }
    const hash = await pbkdf2Hash(password, row.salt);
    if (!timingSafeEqualHex(hash, row.password_hash)) {
      return json({ error: "Invalid username or password" }, 401);
    }
    const exp = Date.now() + SESSION_MAX_AGE_MS;
    const payload = `${username}|${exp}`;
    const sig = await signPayload(payload, env.SESSION_SECRET);
    const token = `${b64urlEncode(new TextEncoder().encode(payload))}.${sig}`;
    const res = json({ ok: true, username });
    res.headers.append(
      "Set-Cookie",
      `session=${token}; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor(SESSION_MAX_AGE_MS / 1000)}; Path=/`
    );
    return res;
  }

  if (path === "/api/logout" && method === "POST") {
    const res = json({ ok: true });
    res.headers.append("Set-Cookie", "session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/");
    return res;
  }

  // Everything below requires a valid session cookie.
  const username = await sessionUsername(request, env);
  if (!username) return json({ error: "Unauthorized" }, 401);

  if (path === "/api/me" && method === "GET") {
    return json({ username });
  }

  if (path === "/api/change-password" && method === "POST") {
    const body = await request.json();
    const currentPassword = body.currentPassword || "";
    const newPassword = body.newPassword || "";
    if (!newPassword || newPassword.length < 6) {
      return json({ error: "New password must be at least 6 characters" }, 400);
    }
    const row = await env.DB.prepare("SELECT salt, password_hash FROM users WHERE username = ?")
      .bind(username).first();
    if (!row) return json({ error: "User not found" }, 404);
    const currentHash = await pbkdf2Hash(currentPassword, row.salt);
    if (!timingSafeEqualHex(currentHash, row.password_hash)) {
      return json({ error: "Current password is incorrect" }, 401);
    }
    const newSaltBytes = crypto.getRandomValues(new Uint8Array(16));
    const newSaltHex = bytesToHex(newSaltBytes);
    const newHash = await pbkdf2Hash(newPassword, newSaltHex);
    await env.DB.prepare(
      "UPDATE users SET salt = ?, password_hash = ?, updated_at = ? WHERE username = ?"
    ).bind(newSaltHex, newHash, Date.now(), username).run();
    return json({ ok: true });
  }

  if (path === "/api/data" && method === "GET") {
    const entriesRes = await env.DB.prepare(
      "SELECT * FROM entries WHERE deleted_at IS NULL ORDER BY created_at DESC"
    ).all();
    const deletedRes = await env.DB.prepare(
      "SELECT * FROM entries WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC"
    ).all();
    const settingsRes = await env.DB.prepare("SELECT * FROM settings").all();
    const targetsRes = await env.DB.prepare("SELECT * FROM po_targets").all();
    const settings = {};
    settingsRes.results.forEach((r) => {
      settings[r.key] = isNaN(r.value) ? r.value : Number(r.value);
    });
    const poTargets = {};
    targetsRes.results.forEach((r) => { poTargets[r.key] = r.target; });
    return json({
      settings,
      poTargets,
      entries: entriesRes.results.map(rowToEntry),
      deleted: deletedRes.results.map(rowToEntry)
    });
  }

  if (path === "/api/entries" && method === "POST") {
    const b = await request.json();
    const id = b.id || crypto.randomUUID();
    const createdAt = b.createdAt || Date.now();
    await env.DB.prepare(
      "INSERT INTO entries (id,supplier,po,invoice,date,truck,qty,status,created_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,NULL)"
    ).bind(id, b.supplier || "", b.po || "", b.invoice || "", b.date || "", b.truck || "", Number(b.qty) || 0, b.status || "Pending", createdAt).run();
    return json({ id, createdAt });
  }

  const entryIdMatch = path.match(/^\/api\/entries\/([^/]+)$/);
  if (entryIdMatch && method === "PUT") {
    const id = entryIdMatch[1];
    const b = await request.json();
    const fields = ["supplier", "po", "invoice", "date", "truck", "qty", "status"];
    const sets = [];
    const vals = [];
    fields.forEach((f) => {
      if (b[f] !== undefined) {
        sets.push(`${f}=?`);
        vals.push(f === "qty" ? Number(b[f]) || 0 : b[f]);
      }
    });
    if (sets.length) {
      vals.push(id);
      await env.DB.prepare(`UPDATE entries SET ${sets.join(",")} WHERE id=?`).bind(...vals).run();
    }
    return json({ ok: true });
  }

  const delMatch = path.match(/^\/api\/entries\/([^/]+)\/delete$/);
  if (delMatch && method === "POST") {
    await env.DB.prepare("UPDATE entries SET deleted_at=? WHERE id=?").bind(Date.now(), delMatch[1]).run();
    return json({ ok: true });
  }

  const restoreMatch = path.match(/^\/api\/entries\/([^/]+)\/restore$/);
  if (restoreMatch && method === "POST") {
    await env.DB.prepare("UPDATE entries SET deleted_at=NULL WHERE id=?").bind(restoreMatch[1]).run();
    return json({ ok: true });
  }

  const purgeMatch = path.match(/^\/api\/entries\/([^/]+)\/purge$/);
  if (purgeMatch && method === "POST") {
    await env.DB.prepare("DELETE FROM entries WHERE id=?").bind(purgeMatch[1]).run();
    return json({ ok: true });
  }

  if (path === "/api/trash/empty" && method === "POST") {
    await env.DB.prepare("DELETE FROM entries WHERE deleted_at IS NOT NULL").run();
    return json({ ok: true });
  }

  if (path === "/api/settings" && method === "PUT") {
    const b = await request.json();
    if (b.totalPending !== undefined) {
      await env.DB.prepare(
        "INSERT INTO settings (key,value) VALUES ('totalPending',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).bind(String(b.totalPending)).run();
    }
    return json({ ok: true });
  }

  if (path === "/api/po-targets" && method === "PUT") {
    const b = await request.json();
    await env.DB.prepare(
      "INSERT INTO po_targets (key,target) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET target=excluded.target"
    ).bind(b.key, Number(b.target) || 0).run();
    return json({ ok: true });
  }

  if (path === "/api/sync" && method === "POST") {
    // Bulk replace — used for the one-time "upload my current data" migration
    // from localStorage, and reusable as a full JSON import.
    const b = await request.json();
    const stmts = [env.DB.prepare("DELETE FROM entries"), env.DB.prepare("DELETE FROM po_targets")];
    (b.entries || []).forEach((e) => {
      stmts.push(
        env.DB.prepare(
          "INSERT INTO entries (id,supplier,po,invoice,date,truck,qty,status,created_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,NULL)"
        ).bind(e.id || crypto.randomUUID(), e.supplier || "", e.po || "", e.invoice || "", e.date || "", e.truck || "", Number(e.qty) || 0, e.status || "Pending", e.createdAt || Date.now())
      );
    });
    (b.deleted || []).forEach((e) => {
      stmts.push(
        env.DB.prepare(
          "INSERT INTO entries (id,supplier,po,invoice,date,truck,qty,status,created_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?)"
        ).bind(e.id || crypto.randomUUID(), e.supplier || "", e.po || "", e.invoice || "", e.date || "", e.truck || "", Number(e.qty) || 0, e.status || "Pending", e.createdAt || Date.now(), e.deletedAt || Date.now())
      );
    });
    if (b.poTargets) {
      Object.keys(b.poTargets).forEach((k) => {
        stmts.push(env.DB.prepare("INSERT INTO po_targets (key,target) VALUES (?,?)").bind(k, Number(b.poTargets[k]) || 0));
      });
    }
    if (b.settings && b.settings.totalPending !== undefined) {
      stmts.push(
        env.DB.prepare(
          "INSERT INTO settings (key,value) VALUES ('totalPending',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        ).bind(String(b.settings.totalPending))
      );
    }
    await env.DB.batch(stmts);
    return json({ ok: true, imported: (b.entries || []).length + (b.deleted || []).length });
  }

  return json({ error: "Not found" }, 404);
}

function rowToEntry(r) {
  return {
    id: r.id, supplier: r.supplier, po: r.po, invoice: r.invoice, date: r.date,
    truck: r.truck, qty: r.qty, status: r.status, createdAt: r.created_at,
    deletedAt: r.deleted_at || undefined
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}

// ---------- Session helpers ----------
async function sessionUsername(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/session=([^;]+)/);
  if (!match) return null;
  const token = decodeURIComponent(match[1]);
  const dot = token.lastIndexOf(".");
  if (dot < 0) return null;
  const payloadB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const payload = new TextDecoder().decode(b64urlDecode(payloadB64));
  const key = await hmacKey(env.SESSION_SECRET);
  const valid = await crypto.subtle.verify("HMAC", key, b64urlDecode(sig), new TextEncoder().encode(payload));
  if (!valid) return null;
  const [uname, expStr] = payload.split("|");
  const exp = Number(expStr);
  if (!exp || Date.now() > exp) return null;
  return uname;
}

async function signPayload(payload, secret) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return b64urlEncode(new Uint8Array(sig));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

// ---------- Password hashing (PBKDF2-SHA256, matches tools/generate-credentials.html) ----------
async function pbkdf2Hash(password, saltHex, iterations = 100000) {
  const salt = hexToBytes(saltHex);
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, keyMaterial, 256);
  return bytesToHex(new Uint8Array(bits));
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------- Byte/base64url helpers ----------
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function b64urlEncode(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
