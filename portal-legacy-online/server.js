const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const dbPath = path.join(DATA_DIR, "portal-legacy.sqlite");
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
 CREATE TABLE IF NOT EXISTS users (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   username TEXT NOT NULL,
   username_key TEXT NOT NULL UNIQUE,
   password_hash TEXT NOT NULL,
   created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
 );
 CREATE TABLE IF NOT EXISTS saves (
   user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
   game_state TEXT NOT NULL,
   updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
 );
 CREATE TABLE IF NOT EXISTS sessions (
   sid TEXT PRIMARY KEY,
   sess TEXT NOT NULL,
   expire INTEGER NOT NULL
 );
 CREATE INDEX IF NOT EXISTS sessions_expire_idx ON sessions(expire);
`);

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  if (process.env.NODE_ENV === "production") {
    throw new Error("SESSION_SECRET doit être défini avec au moins 32 caractères.");
  }
  process.env.SESSION_SECRET = require("crypto").randomBytes(48).toString("hex");
}

class BetterSqliteSessionStore extends session.Store {
  constructor(database) {
    super();
    this.db = database;
    this.getStmt = database.prepare("SELECT sess, expire FROM sessions WHERE sid = ?");
    this.setStmt = database.prepare("INSERT INTO sessions (sid,sess,expire) VALUES (?,?,?) ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expire=excluded.expire");
    this.destroyStmt = database.prepare("DELETE FROM sessions WHERE sid = ?");
    this.touchStmt = database.prepare("UPDATE sessions SET expire = ? WHERE sid = ?");
    setInterval(() => {
      try { database.prepare("DELETE FROM sessions WHERE expire <= ?").run(Date.now()); } catch (_) {}
    }, 60 * 60 * 1000).unref();
  }
  get(sid, cb) {
    try {
      const row = this.getStmt.get(sid);
      if (!row) return cb(null, null);
      if (row.expire <= Date.now()) { this.destroyStmt.run(sid); return cb(null, null); }
      cb(null, JSON.parse(row.sess));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb = () => {}) {
    try {
      const expire = sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 7*24*60*60*1000;
      this.setStmt.run(sid, JSON.stringify(sess), expire);
      cb(null);
    } catch (e) { cb(e); }
  }
  destroy(sid, cb = () => {}) {
    try { this.destroyStmt.run(sid); cb(null); } catch (e) { cb(e); }
  }
  touch(sid, sess, cb = () => {}) {
    try {
      const expire = sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 7*24*60*60*1000;
      this.touchStmt.run(expire, sid); cb(null);
    } catch (e) { cb(e); }
  }
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "512kb", strict: true }));
app.use(session({
  name: "portal.sid",
  secret: process.env.SESSION_SECRET,
  store: new BetterSqliteSessionStore(db),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Trop de tentatives. Attends 15 minutes avant de réessayer." }
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Trop de créations de compte depuis cette connexion. Réessaie plus tard." }
});
const findUser = db.prepare("SELECT id, username, password_hash FROM users WHERE username_key = ?");
const insertUser = db.prepare("INSERT INTO users (username, username_key, password_hash) VALUES (?, ?, ?)");
const getSave = db.prepare("SELECT game_state, updated_at FROM saves WHERE user_id = ?");
const upsertSave = db.prepare("INSERT INTO saves (user_id, game_state, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET game_state=excluded.game_state, updated_at=CURRENT_TIMESTAMP");
const deleteSave = db.prepare("DELETE FROM saves WHERE user_id = ?");

function normalizeUsername(value) {
  return typeof value === "string" ? value.trim() : "";
}
function validateCredentials(req, res, next) {
  const username = normalizeUsername(req.body && req.body.username);
  const password = req.body && req.body.password;
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: "Le pseudo doit contenir 3 à 20 caractères : lettres, chiffres ou _." });
  }
  if (typeof password !== "string" || password.length < 10 || Buffer.byteLength(password, "utf8") > 72) {
    return res.status(400).json({ error: "Le mot de passe doit contenir au moins 10 caractères et au maximum 72 octets." });
  }
  req.credentials = { username, usernameKey: username.toLowerCase(), password };
  next();
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Connecte-toi pour accéder à ta sauvegarde." });
  next();
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
}
function saveSession(req) {
  return new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
}

app.post("/api/register", registerLimiter, validateCredentials, async (req, res, next) => {
  try {
    const { username, usernameKey, password } = req.credentials;
    if (findUser.get(usernameKey)) return res.status(409).json({ error: "Ce pseudo est déjà utilisé. Choisis-en un autre." });
    const hash = await bcrypt.hash(password, 12);
    let result;
    try { result = insertUser.run(username, usernameKey, hash); }
    catch (e) {
      if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "Ce pseudo est déjà utilisé." });
      throw e;
    }
    await regenerateSession(req);
    req.session.userId = Number(result.lastInsertRowid);
    req.session.username = username;
    await saveSession(req);
    res.status(201).json({ username });
  } catch (e) { next(e); }
});

app.post("/api/login", authLimiter, validateCredentials, async (req, res, next) => {
  try {
    const { usernameKey, password } = req.credentials;
    const user = findUser.get(usernameKey);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Pseudo ou mot de passe incorrect." });
    }
    await regenerateSession(req);
    req.session.userId = user.id;
    req.session.username = user.username;
    await saveSession(req);
    res.json({ username: user.username });
  } catch (e) { next(e); }
});

app.get("/api/me", requireAuth, (req, res) => res.json({ username: req.session.username }));
app.get("/api/save", requireAuth, (req, res) => {
  const row = getSave.get(req.session.userId);
  res.json({ save: row ? JSON.parse(row.game_state) : null, updatedAt: row ? row.updated_at : null });
});
app.put("/api/save", requireAuth, (req, res) => {
  const state = req.body;
  if (!state || typeof state !== "object" || Array.isArray(state) || typeof state.name !== "string" || typeof state.chapter !== "number") {
    return res.status(400).json({ error: "Format de sauvegarde invalide." });
  }
  const serialized = JSON.stringify(state);
  if (Buffer.byteLength(serialized, "utf8") > 400 * 1024) {
    return res.status(413).json({ error: "Sauvegarde trop volumineuse." });
  }
  upsertSave.run(req.session.userId, serialized);
  res.json({ ok: true, updatedAt: new Date().toISOString() });
});
app.delete("/api/save", requireAuth, (req, res) => {
  deleteSave.run(req.session.userId);
  res.json({ ok: true });
});
app.post("/api/logout", (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("portal.sid", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict" });
    res.json({ ok: true });
  });
});

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Erreur du serveur. Réessaie dans un instant." });
});

app.listen(PORT, "0.0.0.0", () => console.log(`PORTAL LEGACY en écoute sur ${PORT}`));
