"use strict";
require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { MongoClient, ObjectId } = require("mongodb");

const PORT = Number(process.env.PORT) || 4000;
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "techly";
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_SECURE = process.env.COOKIE_SECURE !== "false";
const FEE = 999;
const SESSION_HOURS = 12;
const COOKIE = "techly_admin";
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString("hex"), 12);

// Missing config must never take the website down: the static site keeps
// working and only the admissions API reports "unavailable".
const CONFIG_ERRORS = [];
if (!MONGODB_URI) CONFIG_ERRORS.push("MONGODB_URI is not set");
if (!JWT_SECRET || JWT_SECRET.length < 32) CONFIG_ERRORS.push("JWT_SECRET must be set (32+ chars)");
CONFIG_ERRORS.forEach(e => console.error("CONFIG:", e));

const client = MONGODB_URI ? new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 10000 }) : null;
let db, Apps, Admins, Settings, Shots;
let dbReady = false;

/* ---------- helpers ---------- */
const pad = n => String(n).padStart(2, "0");
const today = () => { const d = new Date(); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };
const isDate = s => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
const str = (v, max = 200) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const phoneOk = v => /^[6-9]\d{9}$/.test(v);
const emailOk = v => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v);
const newAdmissionId = () => {
  const d = new Date();
  const r = crypto.randomBytes(3).toString("hex").toUpperCase().slice(0, 4);
  return `TAI-${String(d.getFullYear()).slice(2)}${pad(d.getMonth() + 1)}-${r}`;
};
const oid = id => { try { return new ObjectId(String(id)); } catch { return null; } };
const asyncH = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const GENDERS = ["Male", "Female", "Other", "Prefer not to say"];
const QUALS = ["10th / SSLC", "12th / HSC", "Diploma", "Undergraduate (UG)", "Postgraduate (PG)", "Doctorate / PhD", "Other"];
const PROFS = ["Student", "Working Professional", "Business Owner", "Freelancer", "Other"];
const MODES = ["Online", "Offline"];
const PAY = ["pending", "verified", "rejected"];
const ADM = ["submitted", "confirmed", "cancelled"];
const ROLES = ["Owner", "Admin"];

/* Simple in-memory rate limiter (per IP + key). */
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const h = hits.get(key);
  if (!h || now > h.reset) { hits.set(key, { n: 1, reset: now + windowMs }); return false; }
  h.n++;
  return h.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (now > v.reset) hits.delete(k); }, 60000).unref();
const ip = req => req.ip || req.socket.remoteAddress || "?";

/* ---------- app ---------- */
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("X-Frame-Options", "SAMEORIGIN");
  next();
});
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.get("/healthz", (req, res) => res.json({ ok: true, db: dbReady }));
app.use("/api", (req, res, next) => dbReady ? next() : res.status(503).json({ error: "Admissions are temporarily unavailable. Please try again in a few minutes." }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => cb(null, /^image\/(png|jpe?g|webp|gif|heic|heif)$/i.test(file.mimetype))
});

/* ---------- auth ---------- */
function sign(admin) {
  return jwt.sign({ sub: String(admin._id), v: admin.tokenVersion || 0 }, JWT_SECRET, { expiresIn: `${SESSION_HOURS}h` });
}
function setCookie(res, token) {
  res.cookie(COOKIE, token, { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", path: "/api/admin", maxAge: SESSION_HOURS * 3600e3 });
}
const publicAdmin = a => ({ id: String(a._id), email: a.email, name: a.name, role: a.role, active: a.active !== false, lastLogin: a.lastLogin || null, createdAt: a.createdAt || null });

const requireAdmin = asyncH(async (req, res, next) => {
  // CSRF guard: state-changing admin requests must come from our own JS.
  if (req.method !== "GET" && req.get("X-Requested-With") !== "techly") return res.status(403).json({ error: "Bad request origin" });
  const token = req.cookies[COOKIE];
  if (!token) return res.status(401).json({ error: "Not signed in" });
  let p;
  try { p = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: "Session expired. Sign in again." }); }
  const a = await Admins.findOne({ _id: oid(p.sub) });
  if (!a || a.active === false || (a.tokenVersion || 0) !== p.v) return res.status(401).json({ error: "Access removed. Sign in again." });
  req.admin = a;
  next();
});
const requireOwner = (req, res, next) => (req.admin.role === "Owner" ? next() : res.status(403).json({ error: "Owner only" }));

/* ---------- public API ---------- */
const settingsOut = s => ({ upiId: s?.upiId || "", payee: s?.payee || "", whatsapp: s?.whatsapp || "", batchStart: s?.batchStart || "" });

app.get("/api/settings", asyncH(async (req, res) => {
  res.json(settingsOut(await Settings.findOne({ _id: "payment" })));
}));

app.post("/api/applications", (req, res, next) => {
  if (limited("apply:" + ip(req), 10, 3600e3)) return res.status(429).json({ error: "Too many registrations from this network. Try again later." });
  upload.single("screenshot")(req, res, err => {
    if (err) return res.status(400).json({ error: err.code === "LIMIT_FILE_SIZE" ? "Screenshot must be under 5 MB." : "Couldn't read the screenshot." });
    next();
  });
}, asyncH(async (req, res) => {
  const b = req.body || {};
  const d = {
    fullName: str(b.fullName, 100), mobile: str(b.mobile, 10), whatsapp: str(b.whatsapp, 10),
    email: str(b.email, 120).toLowerCase(), age: Number(b.age), gender: str(b.gender), city: str(b.city, 80),
    qualification: str(b.qualification), org: str(b.org, 120), profession: str(b.profession), mode: str(b.mode),
    joiningDate: str(b.joiningDate, 10), why: str(b.why, 600), utr: str(b.utr, 30).toUpperCase(), paymentDate: str(b.paymentDate, 10)
  };
  const T = today();
  const bad = [];
  if (d.fullName.length < 3) bad.push("fullName");
  if (!phoneOk(d.mobile)) bad.push("mobile");
  if (!phoneOk(d.whatsapp)) bad.push("whatsapp");
  if (!emailOk(d.email)) bad.push("email");
  if (!(d.age >= 12 && d.age <= 80)) bad.push("age");
  if (!GENDERS.includes(d.gender)) bad.push("gender");
  if (d.city.length < 2) bad.push("city");
  if (!QUALS.includes(d.qualification)) bad.push("qualification");
  if (!PROFS.includes(d.profession)) bad.push("profession");
  if (!MODES.includes(d.mode)) bad.push("mode");
  if (!isDate(d.joiningDate) || d.joiningDate < T) bad.push("joiningDate");
  if (!/^[A-Z0-9]{6,30}$/.test(d.utr)) bad.push("utr");
  if (!isDate(d.paymentDate) || d.paymentDate > T) bad.push("paymentDate");
  if (b.paidConfirm !== "true") bad.push("paidConfirm");
  if (!req.file) bad.push("screenshot");
  if (bad.length) return res.status(400).json({ error: "Please check the highlighted fields.", fields: bad });

  if (await Apps.findOne({ utr: d.utr }, { projection: { _id: 1 } })) {
    return res.status(409).json({ error: "This Transaction ID / UTR has already been used for a registration. Contact TECHLY if this is a mistake.", fields: ["utr"] });
  }

  const shot = await Shots.insertOne({ data: req.file.buffer, contentType: req.file.mimetype, size: req.file.size, createdAt: new Date() });
  const doc = { ...d, fee: FEE, paidConfirm: true, screenshotId: shot.insertedId, paymentStatus: "pending", admissionStatus: "submitted", createdAt: new Date() };
  for (let i = 0; i < 5; i++) {
    doc.admissionId = newAdmissionId();
    try { await Apps.insertOne(doc); break; }
    catch (e) {
      if (e.code === 11000 && /utr/.test(e.message)) { await Shots.deleteOne({ _id: shot.insertedId }); return res.status(409).json({ error: "This Transaction ID / UTR has already been used.", fields: ["utr"] }); }
      if (e.code !== 11000 || i === 4) throw e;
      delete doc._id;
    }
  }
  res.status(201).json(studentView(doc));
}));

const studentView = a => ({
  admissionId: a.admissionId, fullName: a.fullName, mobile: a.mobile, whatsapp: a.whatsapp, email: a.email, mode: a.mode,
  joiningDate: a.joiningDate, paymentDate: a.paymentDate, utr: a.utr, paymentStatus: a.paymentStatus, admissionStatus: a.admissionStatus
});

/* Students check their own status with Admission ID + mobile. */
app.get("/api/status", asyncH(async (req, res) => {
  if (limited("status:" + ip(req), 60, 3600e3)) return res.status(429).json({ error: "Too many requests" });
  const id = str(req.query.id, 20).toUpperCase(), mobile = str(req.query.mobile, 10);
  const a = id && mobile ? await Apps.findOne({ admissionId: id, mobile }) : null;
  if (!a) return res.status(404).json({ error: "Not found" });
  res.json(studentView(a));
}));

/* ---------- admin: session ---------- */
app.post("/api/admin/login", asyncH(async (req, res) => {
  if (req.get("X-Requested-With") !== "techly") return res.status(403).json({ error: "Bad request origin" });
  const email = str(req.body?.email, 120).toLowerCase(), password = typeof req.body?.password === "string" ? req.body.password : "";
  if (limited("login:" + ip(req), 20, 15 * 60e3) || limited("login:" + email, 8, 15 * 60e3)) {
    return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
  }
  const a = email ? await Admins.findOne({ email }) : null;
  const ok = a ? await bcrypt.compare(password, a.passwordHash) : await bcrypt.compare(password, DUMMY_HASH); // same timing whether or not the email exists
  if (!ok) return res.status(401).json({ error: "Wrong email or password." });
  if (a.active === false) return res.status(403).json({ error: "This account is disabled. Ask an Owner to enable it." });
  await Admins.updateOne({ _id: a._id }, { $set: { lastLogin: new Date() } });
  setCookie(res, sign(a));
  res.json({ me: publicAdmin(a) });
}));

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie(COOKIE, { path: "/api/admin" });
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (req, res) => res.json({ me: publicAdmin(req.admin) }));

app.post("/api/admin/me/password", requireAdmin, asyncH(async (req, res) => {
  const { current, next: nw } = req.body || {};
  if (!(await bcrypt.compare(String(current || ""), req.admin.passwordHash))) return res.status(400).json({ error: "Current password is wrong" });
  if (typeof nw !== "string" || nw.length < 8) return res.status(400).json({ error: "New password needs at least 8 characters" });
  const v = (req.admin.tokenVersion || 0) + 1;
  await Admins.updateOne({ _id: req.admin._id }, { $set: { passwordHash: await bcrypt.hash(nw, 12), tokenVersion: v } });
  setCookie(res, sign({ ...req.admin, tokenVersion: v }));
  res.json({ ok: true });
}));

/* ---------- admin: applications ---------- */
const adminView = a => ({ ...a, id: String(a._id), _id: undefined, screenshotId: undefined, hasScreenshot: !!a.screenshotId });

app.get("/api/admin/applications", requireAdmin, asyncH(async (req, res) => {
  const list = await Apps.find({}).sort({ createdAt: -1 }).limit(5000).toArray();
  res.json({ applications: list.map(adminView) });
}));

app.patch("/api/admin/applications/:id", requireAdmin, asyncH(async (req, res) => {
  const _id = oid(req.params.id);
  if (!_id) return res.status(404).json({ error: "Not found" });
  const b = req.body || {}, set = {};
  if (b.paymentStatus !== undefined) { if (!PAY.includes(b.paymentStatus)) return res.status(400).json({ error: "Bad payment status" }); set.paymentStatus = b.paymentStatus; }
  if (b.admissionStatus !== undefined) { if (!ADM.includes(b.admissionStatus)) return res.status(400).json({ error: "Bad admission status" }); set.admissionStatus = b.admissionStatus; }
  if (b.joiningDate !== undefined) { if (!isDate(b.joiningDate)) return res.status(400).json({ error: "Bad joining date" }); set.joiningDate = b.joiningDate; }
  if (b.paymentDate !== undefined) { if (!isDate(b.paymentDate)) return res.status(400).json({ error: "Bad payment date" }); set.paymentDate = b.paymentDate; }
  if (!Object.keys(set).length) return res.status(400).json({ error: "Nothing to update" });
  if (set.paymentStatus === "verified") { set.verifiedAt = new Date(); set.verifiedBy = req.admin.name || req.admin.email; }
  set.updatedAt = new Date(); set.updatedBy = req.admin.email;
  const r = await Apps.findOneAndUpdate({ _id }, { $set: set }, { returnDocument: "after" });
  if (!r) return res.status(404).json({ error: "Not found" });
  res.json({ application: adminView(r) });
}));

app.get("/api/admin/applications/:id/screenshot", requireAdmin, asyncH(async (req, res) => {
  const a = await Apps.findOne({ _id: oid(req.params.id) }, { projection: { screenshotId: 1 } });
  const s = a?.screenshotId ? await Shots.findOne({ _id: a.screenshotId }) : null;
  if (!s) return res.status(404).send("No screenshot");
  res.set("Content-Type", s.contentType);
  res.set("Cache-Control", "private, max-age=3600");
  res.set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'");
  res.send(Buffer.from(s.data.buffer));
}));

/* ---------- admin: settings (owner) ---------- */
app.put("/api/admin/settings", requireAdmin, requireOwner, asyncH(async (req, res) => {
  const b = req.body || {};
  const s = { upiId: str(b.upiId, 100), payee: str(b.payee, 100), whatsapp: str(b.whatsapp, 10), batchStart: str(b.batchStart, 10) };
  if (s.upiId && !/^[\w.\-]{2,}@[\w.\-]{2,}$/.test(s.upiId)) return res.status(400).json({ error: "Enter a valid UPI ID, e.g. techly@okaxis" });
  if (s.whatsapp && !phoneOk(s.whatsapp)) return res.status(400).json({ error: "Enter a valid 10-digit WhatsApp number" });
  if (s.batchStart && !isDate(s.batchStart)) return res.status(400).json({ error: "Bad batch date" });
  await Settings.updateOne({ _id: "payment" }, { $set: { ...s, updatedAt: new Date(), updatedBy: req.admin.email } }, { upsert: true });
  res.json(settingsOut(s));
}));

/* ---------- admin: users (owner) ---------- */
const activeOwners = () => Admins.countDocuments({ role: "Owner", active: { $ne: false } });

app.get("/api/admin/users", requireAdmin, requireOwner, asyncH(async (req, res) => {
  const list = await Admins.find({}).sort({ email: 1 }).toArray();
  res.json({ users: list.map(publicAdmin) });
}));

app.post("/api/admin/users", requireAdmin, requireOwner, asyncH(async (req, res) => {
  const email = str(req.body?.email, 120).toLowerCase(), name = str(req.body?.name, 60) || email.split("@")[0];
  const role = req.body?.role, password = req.body?.password;
  if (!emailOk(email)) return res.status(400).json({ error: "Enter a valid email" });
  if (!ROLES.includes(role)) return res.status(400).json({ error: "Bad role" });
  if (typeof password !== "string" || password.length < 8) return res.status(400).json({ error: "Password needs at least 8 characters" });
  try {
    await Admins.insertOne({ email, name, role, passwordHash: await bcrypt.hash(password, 12), active: true, tokenVersion: 0, createdAt: new Date(), createdBy: req.admin.email });
  } catch (e) { if (e.code === 11000) return res.status(409).json({ error: "That email is already an admin" }); throw e; }
  res.status(201).json({ ok: true });
}));

app.patch("/api/admin/users/:id", requireAdmin, requireOwner, asyncH(async (req, res) => {
  const _id = oid(req.params.id);
  const u = _id && await Admins.findOne({ _id });
  if (!u) return res.status(404).json({ error: "Not found" });
  const b = req.body || {}, set = {};
  const self = String(u._id) === String(req.admin._id);
  const isLastOwner = u.role === "Owner" && u.active !== false && (await activeOwners()) <= 1;
  if (b.password !== undefined) {
    if (typeof b.password !== "string" || b.password.length < 8) return res.status(400).json({ error: "New password needs at least 8 characters" });
    set.passwordHash = await bcrypt.hash(b.password, 12);
    set.tokenVersion = (u.tokenVersion || 0) + 1;
  }
  if (b.active !== undefined || b.role !== undefined) {
    if (self) return res.status(400).json({ error: "You can't change your own role or status" });
    if (isLastOwner && (b.active === false || b.role === "Admin")) return res.status(400).json({ error: "Keep at least one active Owner" });
  }
  if (b.active !== undefined) { set.active = !!b.active; set.tokenVersion = (u.tokenVersion || 0) + 1; }
  if (b.role !== undefined) { if (!ROLES.includes(b.role)) return res.status(400).json({ error: "Bad role" }); set.role = b.role; }
  if (!Object.keys(set).length) return res.status(400).json({ error: "Nothing to update" });
  await Admins.updateOne({ _id }, { $set: set });
  if (self && set.tokenVersion !== undefined) setCookie(res, sign({ ...u, tokenVersion: set.tokenVersion }));
  res.json({ ok: true });
}));

app.delete("/api/admin/users/:id", requireAdmin, requireOwner, asyncH(async (req, res) => {
  const _id = oid(req.params.id);
  const u = _id && await Admins.findOne({ _id });
  if (!u) return res.status(404).json({ error: "Not found" });
  if (String(u._id) === String(req.admin._id)) return res.status(400).json({ error: "You can't remove yourself" });
  if (u.role === "Owner" && u.active !== false && (await activeOwners()) <= 1) return res.status(400).json({ error: "Keep at least one active Owner" });
  await Admins.deleteOne({ _id });
  res.json({ ok: true });
}));

app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

/* ---------- pages ---------- */
const PUB = path.join(__dirname, "public");
const adminPage = (req, res) => { res.set("Cache-Control", "no-store"); res.sendFile(path.join(PUB, "admin.html")); };
app.get(["/admin", "/admin/", "/courses/admin", "/courses.html/admin"], adminPage);
app.get("/admin.html", (req, res) => res.redirect(301, "/admin"));
app.get("/courses", (req, res) => res.redirect(301, "/courses.html"));
app.use(express.static(PUB, { extensions: ["html"], maxAge: "1h", setHeaders: (res, p) => { if (p.endsWith(".html")) res.set("Cache-Control", "no-cache"); } }));
app.use((req, res) => res.status(404).sendFile(path.join(PUB, "index.html")));

app.use((err, req, res, next) => {
  console.error(err);
  if (req.path.startsWith("/api")) return res.status(500).json({ error: "Server error. Try again." });
  res.status(500).send("Server error");
});

/* ---------- start ---------- */
app.listen(PORT, () => console.log(`Techly running on http://localhost:${PORT}  (admin: /admin)`));

async function connectDb(attempt = 1) {
  if (CONFIG_ERRORS.length) { console.error("Admissions API disabled until the config above is fixed."); return; }
  try {
    await initDb();
    dbReady = true;
    console.log("MongoDB connected, admissions API ready");
  } catch (e) {
    const wait = Math.min(60, 5 * attempt);
    console.error(`MongoDB connection failed (attempt ${attempt}): ${e.message}. Retrying in ${wait}s`);
    setTimeout(() => connectDb(attempt + 1), wait * 1000);
  }
}
connectDb();

async function initDb() {
  await client.connect();
  db = client.db(MONGODB_DB);
  Apps = db.collection("applications");
  Admins = db.collection("admins");
  Settings = db.collection("settings");
  Shots = db.collection("screenshots");
  await Promise.all([
    Apps.createIndex({ admissionId: 1 }, { unique: true }),
    Apps.createIndex({ utr: 1 }, { unique: true }),
    Apps.createIndex({ createdAt: -1 }),
    Admins.createIndex({ email: 1 }, { unique: true })
  ]);
  const owners = await Admins.countDocuments({});
  if (!owners) console.warn("No admin users yet. Create one with: npm run create-owner -- <email> <password> [name]");
}

module.exports = app;
