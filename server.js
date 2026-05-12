const express  = require("express");
const cors     = require("cors");
const path     = require("path");
const http     = require("http");
const crypto   = require("crypto");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { createClient } = require("@libsql/client");
const { Server } = require("socket.io");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

// ────────────────────────────────────────────
// CONFIG
// ────────────────────────────────────────────
const JWT_SECRET         = process.env.JWT_SECRET     || crypto.randomBytes(48).toString("hex");
const JWT_EXPIRES_IN     = "8h";
const APP_JWT_EXPIRES_IN = "30d";
const DEVICE_API_KEY     = process.env.DEVICE_API_KEY || (() => {
    const k = crypto.randomBytes(24).toString("hex");
    console.log("⚠️  DEVICE_API_KEY generata:", k);
    return k;
})();
const BCRYPT_ROUNDS = 10;

if (!process.env.JWT_SECRET)  console.warn("⚠️  JWT_SECRET non impostato.");
if (!process.env.TURSO_URL)   console.error("❌ TURSO_URL mancante!");
if (!process.env.TURSO_TOKEN) console.error("❌ TURSO_TOKEN mancante!");

// ────────────────────────────────────────────
// DATABASE
// ────────────────────────────────────────────
const rawUrl  = process.env.TURSO_URL || "file:local.db";
const tursoUrl = rawUrl.startsWith("http") ? rawUrl.replace(/^https?:\/\//, "libsql://") : rawUrl;

const db = createClient({ url: tursoUrl, authToken: process.env.TURSO_TOKEN || undefined });

async function q(sql, args = [])   { const r = await db.execute({ sql, args }); return r.rows; }
async function run(sql, args = []) { await db.execute(args.length ? { sql, args } : sql); }
async function one(sql, args = []) { return (await q(sql, args))[0]; }

async function initSchema() {
    await db.batch([
        // Dashboard users
        `CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user', active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL, last_login INTEGER)`,
        `CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)`,
        // App users (device owners)
        `CREATE TABLE IF NOT EXISTS app_users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL, last_login INTEGER)`,
        `CREATE TABLE IF NOT EXISTS app_sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)`,
        // Devices & SIMs
        `CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY, nickname TEXT, model TEXT,
            app_user_id TEXT, created_at INTEGER NOT NULL)`,
        `CREATE TABLE IF NOT EXISTS sims (
            id TEXT PRIMARY KEY, device_id TEXT NOT NULL, sim_id TEXT NOT NULL,
            label TEXT, candidate TEXT, last_seen INTEGER, UNIQUE(device_id, sim_id))`,
        // SMS — unica tabella per tutto
        `CREATE TABLE IF NOT EXISTS sms (
            id TEXT PRIMARY KEY, device_id TEXT NOT NULL, sim_id TEXT NOT NULL,
            sender TEXT, message TEXT, timestamp INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
        // Tests
        `CREATE TABLE IF NOT EXISTS tests (
            id TEXT PRIMARY KEY, expected TEXT NOT NULL, device_id TEXT NOT NULL, sim_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING', result TEXT, timeout_ms INTEGER NOT NULL DEFAULT 30000,
            created_at INTEGER NOT NULL, completed_at INTEGER, created_by TEXT, user_id TEXT)`,
        // Schedules
        `CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, expected TEXT NOT NULL,
            device_id TEXT NOT NULL, sim_id TEXT NOT NULL,
            interval_minutes INTEGER NOT NULL, interval_ms INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1, last_run INTEGER, next_run INTEGER,
            created_at INTEGER NOT NULL, created_by TEXT, user_id TEXT)`,
        // Indexes
        `CREATE INDEX IF NOT EXISTS idx_sms_ts        ON sms(timestamp)`,
        `CREATE INDEX IF NOT EXISTS idx_sms_device    ON sms(device_id)`,
        `CREATE INDEX IF NOT EXISTS idx_tests_status  ON tests(status)`,
        `CREATE INDEX IF NOT EXISTS idx_tests_created ON tests(created_at)`,
        `CREATE INDEX IF NOT EXISTS idx_tests_user    ON tests(user_id)`,
    ], "deferred");
    console.log("✅ Schema DB pronto");
}

// ────────────────────────────────────────────
// RUNTIME STATE
// ────────────────────────────────────────────
let devicesOnline = {};
let scheduleJobs  = {};

// ────────────────────────────────────────────
// COUNTRY UTILS
// ────────────────────────────────────────────
const prefixMap = {
    "+39":"IT","+44":"UK","+1":"US","+49":"DE","+33":"FR",
    "+34":"ES","+31":"NL","+48":"PL","+55":"BR","+91":"IN","+86":"CN","+7":"RU"
};
const flagMap = { IT:"🇮🇹",UK:"🇬🇧",US:"🇺🇸",DE:"🇩🇪",FR:"🇫🇷",ES:"🇪🇸",NL:"🇳🇱",PL:"🇵🇱",BR:"🇧🇷",IN:"🇮🇳",CN:"🇨🇳",RU:"🇷🇺" };

function getCountryCode(num) {
    if (!num) return null;
    for (const [p, code] of Object.entries(prefixMap)) {
        const bare = p.slice(1);
        if (num.startsWith(p) || num.startsWith(bare) || num.startsWith("00"+bare)) return code;
    }
    return null;
}

function redactSender(sender) {
    if (!sender) return "—";
    const code = getCountryCode(sender);
    return code ? `${flagMap[code]||""} ${code}` : "🌍 INTL";
}

// ────────────────────────────────────────────
// AUTH HELPERS
// ────────────────────────────────────────────
const signToken    = (u, exp = JWT_EXPIRES_IN) => jwt.sign({ sub: u.id, username: u.username, role: u.role||null }, JWT_SECRET, { expiresIn: exp });
const signAppToken = (u) => jwt.sign({ sub: u.id, username: u.username, type: "app" }, JWT_SECRET, { expiresIn: APP_JWT_EXPIRES_IN });
const verifyJwt    = (t) => { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } };
const timingSafe   = (a,b) => { try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } };
const getBearer    = (req) => { const a = req.headers.authorization; return a?.startsWith("Bearer ") ? a.slice(7) : req.query.token; };

async function requireAuth(req, res, next) {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ error: "Token mancante" });
    const p = verifyJwt(token);
    if (!p || p.type === "app") return res.status(401).json({ error: "Token non valido" });
    const sess = await one("SELECT * FROM sessions WHERE token = ?", [token]);
    if (!sess || sess.revoked) return res.status(401).json({ error: "Sessione non valida" });
    const user = await one("SELECT * FROM users WHERE id = ?", [p.sub]);
    if (!user || !user.active) return res.status(401).json({ error: "Utente non trovato" });
    req.user = user; req.token = token; next();
}

async function requireAdmin(req, res, next) {
    await requireAuth(req, res, () => {
        if (req.user.role !== "admin") return res.status(403).json({ error: "Solo admin" });
        next();
    });
}

async function requireAppAuth(req, res, next) {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ error: "Token mancante" });
    const p = verifyJwt(token);
    if (!p || p.type !== "app") return res.status(401).json({ error: "Token app non valido" });
    const sess = await one("SELECT * FROM app_sessions WHERE token = ?", [token]);
    if (!sess || sess.revoked) return res.status(401).json({ error: "Sessione non valida" });
    const u = await one("SELECT * FROM app_users WHERE id = ?", [p.sub]);
    if (!u) return res.status(401).json({ error: "Utente non trovato" });
    req.appUser = u; req.appToken = token; next();
}

function authDevice(req, res, next) {
    const key = req.headers["x-api-key"] || req.query.api_key;
    if (!key || !timingSafe(key, DEVICE_API_KEY)) return res.status(401).json({ error: "API Key non valida" });
    next();
}

// ────────────────────────────────────────────
// MIDDLEWARE
// ────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ────────────────────────────────────────────
// DASHBOARD AUTH
// ────────────────────────────────────────────
app.post("/auth/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Campi obbligatori" });
        const user  = await one("SELECT * FROM users WHERE username = ?", [username]);
        const dummy = "$2b$10$dummyhashfortimingreasonxxxxx.xx";
        const ok    = user ? await bcrypt.compare(password, user.password_hash) : (await bcrypt.compare(password, dummy), false);
        if (!ok || !user?.active) return res.status(401).json({ error: "Credenziali non valide" });
        const token = signToken(user);
        await run("INSERT INTO sessions (token,user_id,created_at,expires_at,revoked) VALUES (?,?,?,?,0)", [token, user.id, Date.now(), Date.now() + 8*3600000]);
        await run("UPDATE users SET last_login = ? WHERE id = ?", [Date.now(), user.id]);
        console.log(`✅ Login: ${user.username}`);
        res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.post("/auth/logout", requireAuth, async (req, res) => {
    await run("UPDATE sessions SET revoked = 1 WHERE token = ?", [req.token]);
    res.json({ ok: true });
});

app.get("/auth/me", requireAuth, (req, res) => {
    res.json({ id: req.user.id, username: req.user.username, role: req.user.role, lastLogin: req.user.last_login });
});

app.post("/auth/change-password", requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: "Campi obbligatori" });
        if (newPassword.length < 8) return res.status(400).json({ error: "Minimo 8 caratteri" });
        if (!await bcrypt.compare(currentPassword, req.user.password_hash)) return res.status(401).json({ error: "Password errata" });
        await run("UPDATE users SET password_hash = ? WHERE id = ?", [await bcrypt.hash(newPassword, BCRYPT_ROUNDS), req.user.id]);
        await run("UPDATE sessions SET revoked = 1 WHERE user_id = ?", [req.user.id]);
        await run("INSERT INTO sessions (token,user_id,created_at,expires_at,revoked) VALUES (?,?,?,?,0)", [req.token, req.user.id, Date.now(), Date.now() + 8*3600000]);
        res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// ADMIN — UTENTI
// ────────────────────────────────────────────
app.get("/admin/users", requireAdmin, async (req, res) => {
    try { res.json(await q("SELECT id,username,role,active,created_at,last_login FROM users")); }
    catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/users", requireAdmin, async (req, res) => {
    try {
        const { username, password, role = "user" } = req.body;
        if (!username || !password)           return res.status(400).json({ error: "Campi obbligatori" });
        if (password.length < 8)              return res.status(400).json({ error: "Password min 8 caratteri" });
        if (!["user","admin"].includes(role)) return res.status(400).json({ error: "Ruolo non valido" });
        if (await one("SELECT id FROM users WHERE username = ?", [username])) return res.status(409).json({ error: "Username già in uso" });
        const id = crypto.randomUUID();
        await run("INSERT INTO users (id,username,password_hash,role,active,created_at) VALUES (?,?,?,?,1,?)",
            [id, username.trim(), await bcrypt.hash(password, BCRYPT_ROUNDS), role, Date.now()]);
        res.status(201).json({ id, username: username.trim(), role, active: 1 });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch("/admin/users/:id", requireAdmin, async (req, res) => {
    try {
        const user = await one("SELECT * FROM users WHERE id = ?", [req.params.id]);
        if (!user) return res.status(404).json({ error: "Non trovato" });
        if (user.id === req.user.id) return res.status(400).json({ error: "Modifica il tuo account da impostazioni" });
        const { role, active, password } = req.body;
        if (role !== undefined)   await run("UPDATE users SET role = ? WHERE id = ?", [role, user.id]);
        if (active !== undefined) {
            await run("UPDATE users SET active = ? WHERE id = ?", [active ? 1 : 0, user.id]);
            if (!active) await run("UPDATE sessions SET revoked = 1 WHERE user_id = ?", [user.id]);
        }
        if (password) {
            if (password.length < 8) return res.status(400).json({ error: "Password min 8 caratteri" });
            await run("UPDATE users SET password_hash = ? WHERE id = ?", [await bcrypt.hash(password, BCRYPT_ROUNDS), user.id]);
            await run("UPDATE sessions SET revoked = 1 WHERE user_id = ?", [user.id]);
        }
        res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete("/admin/users/:id", requireAdmin, async (req, res) => {
    try {
        const user = await one("SELECT * FROM users WHERE id = ?", [req.params.id]);
        if (!user) return res.status(404).json({ error: "Non trovato" });
        if (user.id === req.user.id) return res.status(400).json({ error: "Non puoi eliminare te stesso" });
        await run("UPDATE sessions SET revoked = 1 WHERE user_id = ?", [user.id]);
        await run("DELETE FROM users WHERE id = ?", [user.id]);
        res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// APP AUTH
// ────────────────────────────────────────────
app.post("/app/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)       return res.status(400).json({ error: "Campi obbligatori" });
        if (username.trim().length < 3)   return res.status(400).json({ error: "Username min 3 caratteri" });
        if (password.length < 6)          return res.status(400).json({ error: "Password min 6 caratteri" });
        if (await one("SELECT id FROM app_users WHERE username = ?", [username.trim()]))
            return res.status(409).json({ error: "Username già in uso" });
        const id = crypto.randomUUID();
        await run("INSERT INTO app_users (id,username,password_hash,created_at) VALUES (?,?,?,?)",
            [id, username.trim(), await bcrypt.hash(password, BCRYPT_ROUNDS), Date.now()]);
        const appUser = await one("SELECT * FROM app_users WHERE id = ?", [id]);
        const token   = signAppToken(appUser);
        await run("INSERT INTO app_sessions (token,user_id,created_at,expires_at,revoked) VALUES (?,?,?,?,0)",
            [token, id, Date.now(), Date.now() + 30*24*3600000]);
        console.log(`📱 Nuovo app user: ${username}`);
        res.status(201).json({ token, user: { id, username: username.trim() } });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/app/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Campi obbligatori" });
        const appUser = await one("SELECT * FROM app_users WHERE username = ?", [username.trim()]);
        const dummy   = "$2b$10$dummyhashfortimingreasonxxxxx.xx";
        const ok      = appUser ? await bcrypt.compare(password, appUser.password_hash) : (await bcrypt.compare(password, dummy), false);
        if (!ok || !appUser) return res.status(401).json({ error: "Credenziali non valide" });
        const token = signAppToken(appUser);
        await run("INSERT INTO app_sessions (token,user_id,created_at,expires_at,revoked) VALUES (?,?,?,?,0)",
            [token, appUser.id, Date.now(), Date.now() + 30*24*3600000]);
        await run("UPDATE app_users SET last_login = ? WHERE id = ?", [Date.now(), appUser.id]);
        const devices = await q("SELECT device_id FROM devices WHERE app_user_id = ?", [appUser.id]);
        console.log(`📱 App login: ${appUser.username}`);
        res.json({ token, user: { id: appUser.id, username: appUser.username, deviceIds: devices.map(d => d.device_id) } });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/app/logout", requireAppAuth, async (req, res) => {
    await run("UPDATE app_sessions SET revoked = 1 WHERE token = ?", [req.appToken]);
    res.json({ ok: true });
});

app.get("/app/me", requireAppAuth, async (req, res) => {
    try {
        const devices = await q("SELECT * FROM devices WHERE app_user_id = ?", [req.appUser.id]);
        const result  = await Promise.all(devices.map(async d => {
            const online = Object.values(devicesOnline).find(dev => dev.deviceId === d.device_id);
            const sims   = await q("SELECT * FROM sims WHERE device_id = ?", [d.device_id]);
            return { deviceId: d.device_id, nickname: d.nickname || d.device_id, online: !!online, model: d.model || "unknown", sims: sims.map(s => ({ simId: s.sim_id, label: s.label, candidate: s.candidate })) };
        }));
        res.json({ id: req.appUser.id, username: req.appUser.username, devices: result });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch("/app/device/:deviceId/rename", requireAppAuth, async (req, res) => {
    try {
        const { nickname } = req.body;
        if (!nickname?.trim()) return res.status(400).json({ error: "Nickname obbligatorio" });
        const device = await one("SELECT * FROM devices WHERE device_id = ?", [req.params.deviceId]);
        if (!device || device.app_user_id !== req.appUser.id) return res.status(403).json({ error: "Non autorizzato" });
        await run("UPDATE devices SET nickname = ? WHERE device_id = ?", [nickname.trim(), req.params.deviceId]);
        io.emit("device_renamed", { deviceId: req.params.deviceId, nickname: nickname.trim() });
        res.json({ ok: true, nickname: nickname.trim() });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/app/sms", requireAppAuth, async (req, res) => {
    try {
        const rows = await q("SELECT s.* FROM sms s JOIN devices d ON s.device_id = d.device_id WHERE d.app_user_id = ? ORDER BY s.timestamp DESC LIMIT 500", [req.appUser.id]);
        res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/app/sims", requireAppAuth, async (req, res) => {
    try {
        const rows = await q("SELECT si.* FROM sims si JOIN devices d ON si.device_id = d.device_id WHERE d.app_user_id = ?", [req.appUser.id]);
        res.json(rows);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// SOCKET.IO
// ────────────────────────────────────────────
io.use((socket, next) => {
    const deviceKey = socket.handshake.auth?.apiKey;
    if (deviceKey && timingSafe(deviceKey, DEVICE_API_KEY)) {
        socket.isDevice = true;
        const appToken = socket.handshake.auth?.appToken;
        if (appToken) { try { const p = jwt.verify(appToken, JWT_SECRET); if (p.type === "app") socket.appUserId = p.sub; } catch {} }
        return next();
    }
    const token = socket.handshake.auth?.token;
    if (token && verifyJwt(token)) { socket.userId = verifyJwt(token).sub; return next(); }
    next(new Error("Non autorizzato"));
});

io.on("connection", (socket) => {
    console.log(socket.isDevice ? `🔌 Device: ${socket.id}` : `🔌 Dashboard: ${socket.id}`);

    socket.on("register_device", async (data) => {
        if (!socket.isDevice || !data?.deviceId) return;
        try {
            const old = Object.entries(devicesOnline).find(([,d]) => d.deviceId === data.deviceId);
            if (old) delete devicesOnline[old[0]];
            devicesOnline[socket.id] = { deviceId: data.deviceId, model: data.model || "unknown", sims: [], connectedAt: Date.now(), appUserId: socket.appUserId || null };
            const existing = await one("SELECT * FROM devices WHERE device_id = ?", [data.deviceId]);
            if (!existing) {
                await run("INSERT INTO devices (device_id,nickname,model,app_user_id,created_at) VALUES (?,?,?,?,?)", [data.deviceId, null, data.model || "unknown", socket.appUserId || null, Date.now()]);
            } else {
                await run("UPDATE devices SET model = ?, app_user_id = COALESCE(?, app_user_id) WHERE device_id = ?", [data.model || existing.model, socket.appUserId || null, data.deviceId]);
            }
            for (const sim of (data.sims || [])) {
                const existingSim = await one("SELECT * FROM sims WHERE device_id = ? AND sim_id = ?", [data.deviceId, sim.simId]);
                if (!existingSim) await run("INSERT INTO sims (id,device_id,sim_id,label,candidate,last_seen) VALUES (?,?,?,?,?,?)", [crypto.randomUUID(), data.deviceId, sim.simId, null, sim.number?.trim() || null, Date.now()]);
                else if (sim.number?.trim()) await run("UPDATE sims SET candidate = ?, last_seen = ? WHERE device_id = ? AND sim_id = ?", [sim.number.trim(), Date.now(), data.deviceId, sim.simId]);
                devicesOnline[socket.id].sims.push({ simId: sim.simId });
            }
            console.log(`📱 Online: ${data.deviceId} | ${data.model} | user: ${socket.appUserId || "anon"}`);
        } catch(e) { console.error("register_device error:", e.message); }
    });

    socket.on("disconnect", () => {
        const d = devicesOnline[socket.id];
        if (d) { console.log(`❌ Offline: ${d.deviceId}`); delete devicesOnline[socket.id]; }
    });
});

// ────────────────────────────────────────────
// SMS — riceve da device, salva, controlla test
// ────────────────────────────────────────────
app.post("/sms", authDevice, async (req, res) => {
    try {
        const sms = req.body;
        if (!sms?.deviceId || !sms?.simId) return res.status(400).json({ error: "Campi obbligatori" });

        const id = crypto.randomUUID();
        const ts = sms.timestamp || Date.now();

        await run("INSERT INTO sms (id,device_id,sim_id,sender,message,timestamp,created_at) VALUES (?,?,?,?,?,?,?)",
            [id, sms.deviceId, sms.simId, sms.sender || null, sms.message || null, ts, Date.now()]);

        // Upsert SIM last_seen
        const existingSim = await one("SELECT id FROM sims WHERE device_id = ? AND sim_id = ?", [sms.deviceId, sms.simId]);
        if (!existingSim) await run("INSERT INTO sims (id,device_id,sim_id,label,candidate,last_seen) VALUES (?,?,?,?,?,?)", [crypto.randomUUID(), sms.deviceId, sms.simId, null, null, Date.now()]);
        else await run("UPDATE sims SET last_seen = ? WHERE device_id = ? AND sim_id = ?", [Date.now(), sms.deviceId, sms.simId]);

        // Update online device
        const dev = Object.values(devicesOnline).find(d => d.deviceId === sms.deviceId);
        if (dev && !dev.sims.find(s => s.simId === sms.simId)) dev.sims.push({ simId: sms.simId });

        io.emit("new_sms", { ...sms, id, timestamp: ts });

        // Check pending tests
        const pending = await q("SELECT * FROM tests WHERE status = 'PENDING'");
        for (const test of pending) {
            if (test.device_id === sms.deviceId && test.sim_id === sms.simId &&
                (sms.message || "").toLowerCase().includes((test.expected || "").toLowerCase())) {
                await run("UPDATE tests SET status='PASS', result=?, completed_at=? WHERE id=?", [sms.message, Date.now(), test.id]);
                io.emit("test_update", { id: test.id, status: "PASS", result: sms.message, completedAt: Date.now() });
                console.log(`✅ TEST PASS: ${test.id}`);
            }
        }

        res.json({ status: "ok", id });
    } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// GET /sms — admin vede tutti, user vede tutti (SMS è pannello pubblico, i test sono separati)
app.get("/sms", requireAuth, async (req, res) => {
    try {
        const rows = await q("SELECT * FROM sms ORDER BY timestamp DESC LIMIT 1000");
        if (req.user.role === "admin") return res.json(rows);
        // user: oscura il sender reale
        res.json(rows.map(s => ({ ...s, sender: redactSender(s.sender) })));
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// SIMS
// ────────────────────────────────────────────
app.get("/sims", requireAuth, async (req, res) => {
    try {
        const all = await q("SELECT * FROM sims");
        if (req.user.role === "admin") return res.json(all.map(s => ({ simId: s.sim_id, deviceId: s.device_id, label: s.label, candidate: s.candidate })));

        // User: restituisce ogni SIM con il numero reale (oscurato solo per SMS, non per selezione test)
        // Filtra solo SIM con numero configurato
        const configured = all.filter(s => s.label?.trim() || s.candidate?.trim());
        res.json(configured.map(s => ({
            simId:     s.sim_id,
            deviceId:  s.device_id,
            label:     s.label?.trim() || s.candidate?.trim(),
            candidate: s.candidate,
            isRedacted: false
        })));
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/set-sim-label", requireAuth, async (req, res) => {
    try {
        const { deviceId, simId, label } = req.body;
        if (!deviceId || !simId) return res.status(400).json({ error: "Campi obbligatori" });
        await run("UPDATE sims SET label = ?, candidate = NULL WHERE device_id = ? AND sim_id = ?", [label?.trim() || null, deviceId, simId]);
        res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// DEVICES
// ────────────────────────────────────────────
app.get("/devices-online", requireAuth, async (req, res) => {
    try {
        if (req.user.role === "admin") {
            const result = await Promise.all(Object.values(devicesOnline).map(async d => {
                const meta = await one("SELECT * FROM devices WHERE device_id = ?", [d.deviceId]);
                const sims = await q("SELECT * FROM sims WHERE device_id = ?", [d.deviceId]);
                return { ...d, nickname: meta?.nickname || null, sims: sims.map(s => ({ simId: s.sim_id, label: s.label, candidate: s.candidate })) };
            }));
            return res.json(result);
        }
        const byCountry = {};
        for (const device of Object.values(devicesOnline)) {
            const sims = await q("SELECT * FROM sims WHERE device_id = ?", [device.deviceId]);
            sims.forEach(sim => {
                const code = getCountryCode(sim.label || sim.candidate || "") || "OTHER";
                const flag = flagMap[code] || "🌍";
                const key  = `${flag} ${code}`;
                if (!byCountry[key]) byCountry[key] = { country: key, sims: 0 };
                byCountry[key].sims++;
            });
        }
        res.json({ redacted: true, summary: Object.values(byCountry), total: Object.keys(devicesOnline).length });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch("/device/:deviceId/rename", requireAdmin, async (req, res) => {
    try {
        const { nickname } = req.body;
        if (!nickname?.trim()) return res.status(400).json({ error: "Nickname obbligatorio" });
        await run("UPDATE devices SET nickname = ? WHERE device_id = ?", [nickname.trim(), req.params.deviceId]);
        io.emit("device_renamed", { deviceId: req.params.deviceId, nickname: nickname.trim() });
        res.json({ ok: true, nickname: nickname.trim() });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// TESTS
// Regola d'oro:
//   - user vede SOLO i propri test (WHERE user_id = req.user.id)
//   - admin vede TUTTI i test
// ────────────────────────────────────────────
app.post("/test", requireAuth, async (req, res) => {
    try {
        const { expected, phoneNumber, deviceId, simId } = req.body;
        if (!expected) return res.status(400).json({ error: "Testo atteso obbligatorio" });

        let targetDeviceId = deviceId;
        let targetSimId    = simId;

        // Se l'utente passa un numero di telefono, troviamo device+sim automaticamente
        if (phoneNumber && !deviceId) {
            const norm    = phoneNumber.replace(/\s/g, "").trim();
            const allSims = await q("SELECT * FROM sims");

            // Cerca corrispondenza esatta per numero
            let match = allSims.find(s => {
                const num = (s.label || s.candidate || "").replace(/\s/g, "");
                if (!num) return false;
                const a = num.replace(/[^0-9]/g, "").slice(-9);
                const b = norm.replace(/[^0-9]/g, "").slice(-9);
                return a === b && a.length >= 6;
            });

            // Se non trova corrispondenza esatta, cerca per prefisso paese e assegna random
            if (!match && norm.startsWith("+")) {
                const simsByCountry = allSims.filter(s => {
                    const num = (s.label || s.candidate || "").replace(/\s/g, "");
                    return num && num.replace(/[^0-9]/g, "").startsWith(norm.slice(1, 4));
                });
                if (simsByCountry.length > 0) {
                    match = simsByCountry[Math.floor(Math.random() * simsByCountry.length)];
                    console.log(`🎲 SIM random assegnata: ${match.sim_id} su ${match.device_id}`);
                }
            }

            if (!match) return res.status(404).json({ error: `Nessuna SIM disponibile per ${phoneNumber}` });
            targetDeviceId = match.device_id;
            targetSimId    = match.sim_id;
            console.log(`📍 SIM trovata: ${match.label || match.candidate} → ${match.device_id}/${match.sim_id}`);
        }

        if (!targetDeviceId || !targetSimId) return res.status(400).json({ error: "Specifica un numero di telefono o deviceId+simId" });

        const id  = crypto.randomUUID();
        const now = Date.now();
        await run("INSERT INTO tests (id,expected,device_id,sim_id,status,timeout_ms,created_at,created_by,user_id) VALUES (?,?,?,?,?,?,?,?,?)",
            [id, expected.trim(), targetDeviceId, targetSimId, "PENDING", 30000, now, req.user.username, req.user.id]);
        // Recupera il numero di telefono della SIM per mostrarlo subito
        const simInfo = await one("SELECT * FROM sims WHERE device_id = ? AND sim_id = ?", [targetDeviceId, targetSimId]);
        const phoneLabel = simInfo?.label?.trim() || simInfo?.candidate?.trim() || targetSimId;
        console.log(`🧪 Test creato: ${id} | user=${req.user.username} | device=${targetDeviceId} sim=${targetSimId} phone=${phoneLabel}`);
        res.json({ id, expected: expected.trim(), deviceId: targetDeviceId, simId: targetSimId, phoneLabel, status: "PENDING", createdAt: now, timeout: 30000, createdBy: req.user.username });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get("/tests", requireAuth, async (req, res) => {
    try {
        const isAdmin = req.user.role === "admin";
        const { status, from, to } = req.query;

        let sql  = "SELECT * FROM tests WHERE 1=1";
        const args = [];

        // REGOLA D'ORO: user vede solo i propri, admin vede tutto
        if (!isAdmin) {
            sql += " AND user_id = ?";
            args.push(req.user.id);
        }

        if (status) { sql += " AND status = ?";      args.push(status); }
        if (from)   { sql += " AND created_at >= ?"; args.push(Number(from)); }
        if (to)     { sql += " AND created_at <= ?"; args.push(Number(to)); }
        sql += " ORDER BY created_at DESC LIMIT 500";

        console.log(`📋 GET /tests | user=${req.user.username} | isAdmin=${isAdmin} | sql: ...${sql.slice(-50)}`);

        const rows = await q(sql, args);
        // Arricchisci con il numero di telefono della SIM
        const enriched = await Promise.all(rows.map(async t => {
            const sim = await one("SELECT * FROM sims WHERE device_id = ? AND sim_id = ?", [t.device_id, t.sim_id]);
            const phoneLabel = sim?.label?.trim() || sim?.candidate?.trim() || t.sim_id;
            return {
                id: t.id, expected: t.expected, deviceId: t.device_id, simId: t.sim_id,
                phoneLabel,
                status: t.status, result: t.result, createdAt: t.created_at,
                completedAt: t.completed_at, timeout: t.timeout_ms, createdBy: t.created_by
            };
        }));
        res.json(enriched);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// STATS
// ────────────────────────────────────────────
app.get("/stats", requireAuth, async (req, res) => {
    try {
        const now    = Date.now();
        const recent = await q("SELECT * FROM tests WHERE created_at > ?", [now - 24*3600000]);
        const week   = await q("SELECT * FROM tests WHERE created_at > ?", [now - 7*24*3600000]);
        const pass24 = recent.filter(t => t.status === "PASS").length;
        const fail24 = recent.filter(t => t.status === "FAIL").length;
        const total24 = recent.length;
        const deliveryRate = total24 > 0 ? Math.round(pass24 / total24 * 100) : null;
        const passTime = recent.filter(t => t.status === "PASS" && t.completed_at);
        const avgLatency = passTime.length > 0 ? Math.round(passTime.reduce((a,t) => a + (t.completed_at - t.created_at), 0) / passTime.length) : null;

        const countryStats = {};
        for (const test of week) {
            const sim  = await one("SELECT * FROM sims WHERE device_id = ? AND sim_id = ?", [test.device_id, test.sim_id]);
            const code = getCountryCode(sim?.label || sim?.candidate || "") || "OTHER";
            if (!countryStats[code]) countryStats[code] = { pass:0, fail:0, latencies:[] };
            if (test.status === "PASS") { countryStats[code].pass++; if (test.completed_at) countryStats[code].latencies.push(test.completed_at - test.created_at); }
            if (test.status === "FAIL") countryStats[code].fail++;
        }

        const byCountry = Object.entries(countryStats).map(([code, d]) => ({
            country: `${flagMap[code]||"🌍"} ${code}`,
            pass: d.pass, fail: d.fail, total: d.pass + d.fail,
            deliveryRate: d.pass + d.fail > 0 ? Math.round(d.pass/(d.pass+d.fail)*100) : null,
            avgLatency:   d.latencies.length > 0 ? Math.round(d.latencies.reduce((a,b)=>a+b,0)/d.latencies.length) : null
        }));

        const hourly = Array.from({length:24}, (_,i) => {
            const from = now - (24-i)*3600000; const to = from + 3600000;
            const b = recent.filter(t => t.created_at >= from && t.created_at < to);
            return { hour: new Date(from).getHours(), pass: b.filter(t=>t.status==="PASS").length, fail: b.filter(t=>t.status==="FAIL").length };
        });

        const totalSims = await q("SELECT COUNT(*) as c FROM sims");
        res.json({ summary: { total24, pass24, fail24, deliveryRate, avgLatency, totalSims: Number(totalSims[0].c), onlineDevices: Object.keys(devicesOnline).length }, byCountry, hourly });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// SCHEDULES
// ────────────────────────────────────────────
async function startScheduleJob(s) {
    if (scheduleJobs[s.id]) clearInterval(scheduleJobs[s.id]);
    if (!s.enabled) return;
    const tick = async () => {
        try {
            const now = Date.now();
            const id  = crypto.randomUUID();
            await run("UPDATE schedules SET last_run=?, next_run=? WHERE id=?", [now, now + s.interval_ms, s.id]);
            await run("INSERT INTO tests (id,expected,device_id,sim_id,status,timeout_ms,created_at,created_by,user_id) VALUES (?,?,?,?,?,?,?,?,?)",
                [id, s.expected, s.device_id, s.sim_id, "PENDING", 60000, now, `⏱ ${s.name}`, s.user_id || null]);
            io.emit("new_test", { id, expected: s.expected, deviceId: s.device_id, simId: s.sim_id, status: "PENDING", createdAt: now });
            console.log(`🗓 Schedule run: ${s.name}`);
        } catch(e) { console.error("Schedule error:", e.message); }
    };
    scheduleJobs[s.id] = setInterval(tick, s.interval_ms);
}

app.get("/schedules", requireAuth,  async (req, res) => {
    try { res.json(await q("SELECT * FROM schedules")); } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post("/schedules", requireAdmin, async (req, res) => {
    try {
        const { name, expected, deviceId, simId, intervalMinutes } = req.body;
        if (!name || !expected || !deviceId || !simId || !intervalMinutes) return res.status(400).json({ error: "Campi obbligatori" });
        const intervalMs = Math.max(5, parseInt(intervalMinutes)) * 60000;
        const id = crypto.randomUUID();
        const now = Date.now();
        await run("INSERT INTO schedules (id,name,expected,device_id,sim_id,interval_minutes,interval_ms,enabled,next_run,created_at,created_by,user_id) VALUES (?,?,?,?,?,?,?,1,?,?,?,?)",
            [id, name.trim(), expected.trim(), deviceId, simId, parseInt(intervalMinutes), intervalMs, now + intervalMs, now, req.user.username, req.user.id]);
        const s = await one("SELECT * FROM schedules WHERE id = ?", [id]);
        await startScheduleJob(s);
        res.status(201).json(s);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch("/schedules/:id", requireAdmin, async (req, res) => {
    try {
        const s = await one("SELECT * FROM schedules WHERE id = ?", [req.params.id]);
        if (!s) return res.status(404).json({ error: "Non trovato" });
        if (req.body.enabled !== undefined) {
            const enabled = req.body.enabled ? 1 : 0;
            await run("UPDATE schedules SET enabled = ? WHERE id = ?", [enabled, s.id]);
            if (enabled) await startScheduleJob({ ...s, enabled: true });
            else { clearInterval(scheduleJobs[s.id]); delete scheduleJobs[s.id]; }
        }
        res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete("/schedules/:id", requireAdmin, async (req, res) => {
    try {
        clearInterval(scheduleJobs[req.params.id]);
        delete scheduleJobs[req.params.id];
        await run("DELETE FROM schedules WHERE id = ?", [req.params.id]);
        res.json({ ok: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ────────────────────────────────────────────
// BACKGROUND JOBS
// ────────────────────────────────────────────
setInterval(async () => {
    try {
        const now = Date.now();
        const pending = await q("SELECT * FROM tests WHERE status = 'PENDING'");
        for (const test of pending) {
            if (now - test.created_at > test.timeout_ms) {
                await run("UPDATE tests SET status='FAIL', completed_at=? WHERE id=?", [now, test.id]);
                io.emit("test_update", { id: test.id, status: "FAIL", completedAt: now });
                console.log(`❌ TEST FAIL timeout: ${test.id}`);
            }
        }
    } catch(e) { console.error("Timeout job:", e.message); }
}, 5000);

setInterval(async () => {
    try { await run("DELETE FROM sessions WHERE expires_at < ? OR revoked = 1", [Date.now()]); }
    catch(e) { console.error("Clean sessions:", e.message); }
}, 3600000);

// ────────────────────────────────────────────
// SEED + START
// ────────────────────────────────────────────
async function seed() {
    const adminUser = process.env.ADMIN_USERNAME || "admin";
    if (!await one("SELECT id FROM users WHERE username = ?", [adminUser])) {
        const adminPass = process.env.ADMIN_PASSWORD || (() => {
            const p = crypto.randomBytes(12).toString("base64url");
            console.log("────────────────────────────────────");
            console.log("👤 Admin creato automaticamente");
            console.log(`   Username: ${adminUser}`);
            console.log(`   Password: ${p}`);
            console.log("────────────────────────────────────");
            return p;
        })();
        await run("INSERT INTO users (id,username,password_hash,role,active,created_at) VALUES (?,?,?,?,1,?)",
            [crypto.randomUUID(), adminUser, await bcrypt.hash(adminPass, BCRYPT_ROUNDS), "admin", Date.now()]);
    }
    const schedules = await q("SELECT * FROM schedules WHERE enabled = 1");
    for (const s of schedules) await startScheduleJob(s);
    console.log(`🗓 ${schedules.length} schedule(s) riavviati`);
}

const PORT = process.env.PORT || 3000;
async function start() {
    try {
        await initSchema();
        await seed();
        server.listen(PORT, () => {
            console.log(`🚀 Server su porta ${PORT}`);
            console.log(`📱 DEVICE_API_KEY: ${DEVICE_API_KEY}`);
            console.log(`🗄  Turso: ${tursoUrl}`);
        });
    } catch(e) { console.error("❌ Errore avvio:", e); process.exit(1); }
}
start();