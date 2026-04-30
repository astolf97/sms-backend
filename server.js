const express  = require("express");
const cors     = require("cors");
const path     = require("path");
const http     = require("http");
const crypto   = require("crypto");
const bcrypt   = require("bcrypt");
const jwt      = require("jsonwebtoken");
const { Server } = require("socket.io");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

// ────────────────────────────────────────────
// ⚙️  CONFIG
// ────────────────────────────────────────────
const JWT_SECRET     = process.env.JWT_SECRET     || crypto.randomBytes(48).toString("hex");
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "8h";
const DEVICE_API_KEY = process.env.DEVICE_API_KEY || (() => {
    const k = crypto.randomBytes(24).toString("hex");
    console.log("⚠️  DEVICE_API_KEY non impostata. Chiave generata:", k);
    return k;
})();
const BCRYPT_ROUNDS  = 10;

if (!process.env.JWT_SECRET) {
    console.warn("⚠️  JWT_SECRET non impostato — i token saranno invalidati al riavvio.");
}

// ────────────────────────────────────────────
// 🗄  STORAGE (in-memory)
// ────────────────────────────────────────────
let users         = [];
let sessions      = [];
let devicesOnline = {};
let smsList       = [];
let tests         = [];
let sims          = [];

// ── Seed admin al primo avvio
async function seedAdmin() {
    const adminUser = process.env.ADMIN_USERNAME || "admin";
    const adminPass = process.env.ADMIN_PASSWORD || (() => {
        const p = crypto.randomBytes(12).toString("base64url");
        console.log("──────────────────────────────────────");
        console.log("👤 Account admin creato automaticamente");
        console.log(`   Username : ${adminUser}`);
        console.log(`   Password : ${p}`);
        console.log("   Cambiala subito dal pannello Admin!");
        console.log("──────────────────────────────────────");
        return p;
    })();

    const hash = await bcrypt.hash(adminPass, BCRYPT_ROUNDS);
    users.push({
        id:           crypto.randomUUID(),
        username:     adminUser,
        passwordHash: hash,
        role:         "admin",
        createdAt:    Date.now(),
        lastLogin:    null,
        active:       true
    });
}

// ────────────────────────────────────────────
// 🛡  AUTH HELPERS
// ────────────────────────────────────────────
function signToken(user) {
    return jwt.sign(
        { sub: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

function verifyToken(token) {
    try { return jwt.verify(token, JWT_SECRET); }
    catch { return null; }
}

function extractToken(req) {
    const auth = req.headers.authorization;
    if (auth?.startsWith("Bearer ")) return auth.slice(7);
    return req.query.token || null;
}

function safeCompare(a, b) {
    try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
    catch { return false; }
}

function requireAuth(req, res, next) {
    const token = extractToken(req);
    if (!token) return res.status(401).json({ error: "Token mancante" });

    const payload = verifyToken(token);
    if (!payload)  return res.status(401).json({ error: "Token non valido o scaduto" });

    const revoked = sessions.find(s => s.token === token && s.revoked);
    if (revoked)   return res.status(401).json({ error: "Sessione revocata" });

    const user = users.find(u => u.id === payload.sub && u.active);
    if (!user)     return res.status(401).json({ error: "Utente non trovato o disabilitato" });

    req.user  = user;
    req.token = token;
    next();
}

function requireAdmin(req, res, next) {
    requireAuth(req, res, () => {
        if (req.user.role !== "admin") return res.status(403).json({ error: "Solo admin" });
        next();
    });
}

function authDevice(req, res, next) {
    const key = req.headers["x-api-key"] || req.query.api_key;
    if (!key || !safeCompare(key, DEVICE_API_KEY)) {
        return res.status(401).json({ error: "API Key non valida" });
    }
    next();
}

// ────────────────────────────────────────────
// ⚙️  MIDDLEWARE
// ────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ────────────────────────────────────────────
// 🔐 AUTH ENDPOINTS
// ────────────────────────────────────────────
app.post("/auth/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Campi obbligatori" });

    const user = users.find(u => u.username === username);
    const dummyHash = "$2b$10$dummyhashfortimingreasonxxxxx.xx";

    const valid = user
        ? await bcrypt.compare(password, user.passwordHash)
        : (await bcrypt.compare(password, dummyHash), false);

    if (!valid || !user?.active) return res.status(401).json({ error: "Credenziali non valide" });

    const token = signToken(user);
    sessions.push({ token, userId: user.id, createdAt: Date.now(), expiresAt: Date.now() + 8 * 3600000, revoked: false });
    user.lastLogin = Date.now();

    console.log(`✅ Login: ${user.username} (${user.role})`);
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

app.post("/auth/logout", requireAuth, (req, res) => {
    const s = sessions.find(s => s.token === req.token);
    if (s) s.revoked = true;
    console.log(`👋 Logout: ${req.user.username}`);
    res.json({ ok: true });
});

app.get("/auth/me", requireAuth, (req, res) => {
    res.json({ id: req.user.id, username: req.user.username, role: req.user.role, lastLogin: req.user.lastLogin });
});

app.post("/auth/change-password", requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: "Campi obbligatori" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Minimo 8 caratteri" });

    const valid = await bcrypt.compare(currentPassword, req.user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Password attuale errata" });

    req.user.passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    sessions.forEach(s => { if (s.userId === req.user.id && s.token !== req.token) s.revoked = true; });

    console.log(`🔑 Password cambiata: ${req.user.username}`);
    res.json({ ok: true });
});

// ────────────────────────────────────────────
// 👥 ADMIN — GESTIONE UTENTI
// ────────────────────────────────────────────
app.get("/admin/users", requireAdmin, (req, res) => {
    res.json(users.map(u => ({
        id: u.id, username: u.username, role: u.role,
        active: u.active, createdAt: u.createdAt, lastLogin: u.lastLogin
    })));
});

app.post("/admin/users", requireAdmin, async (req, res) => {
    const { username, password, role = "user" } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Campi obbligatori" });
    if (password.length < 8) return res.status(400).json({ error: "Password minimo 8 caratteri" });
    if (!["user", "admin"].includes(role)) return res.status(400).json({ error: "Ruolo non valido" });
    if (users.find(u => u.username === username)) return res.status(409).json({ error: "Username già in uso" });

    const user = {
        id: crypto.randomUUID(), username: username.trim(),
        passwordHash: await bcrypt.hash(password, BCRYPT_ROUNDS),
        role, createdAt: Date.now(), lastLogin: null, active: true
    };

    users.push(user);
    console.log(`👤 Nuovo utente: ${user.username} (${user.role})`);
    res.status(201).json({ id: user.id, username: user.username, role: user.role, active: user.active, createdAt: user.createdAt });
});

app.patch("/admin/users/:id", requireAdmin, async (req, res) => {
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: "Utente non trovato" });
    if (user.id === req.user.id) return res.status(400).json({ error: "Usa /auth/change-password per il tuo account" });

    const { role, active, password } = req.body;

    if (role !== undefined) {
        if (!["user", "admin"].includes(role)) return res.status(400).json({ error: "Ruolo non valido" });
        user.role = role;
    }

    if (active !== undefined) {
        user.active = Boolean(active);
        if (!user.active) sessions.forEach(s => { if (s.userId === user.id) s.revoked = true; });
    }

    if (password) {
        if (password.length < 8) return res.status(400).json({ error: "Password minimo 8 caratteri" });
        user.passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        sessions.forEach(s => { if (s.userId === user.id) s.revoked = true; });
    }

    console.log(`✏️  Utente aggiornato: ${user.username}`);
    res.json({ ok: true, username: user.username, role: user.role, active: user.active });
});

app.delete("/admin/users/:id", requireAdmin, (req, res) => {
    const idx = users.findIndex(u => u.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "Utente non trovato" });
    if (users[idx].id === req.user.id) return res.status(400).json({ error: "Non puoi eliminare te stesso" });

    const removed = users.splice(idx, 1)[0];
    sessions.forEach(s => { if (s.userId === removed.id) s.revoked = true; });

    console.log(`🗑  Utente eliminato: ${removed.username}`);
    res.json({ ok: true });
});

// ────────────────────────────────────────────
// 🔌 SOCKET.IO
// ────────────────────────────────────────────
io.use((socket, next) => {
    const deviceKey = socket.handshake.auth?.apiKey;
    if (deviceKey && safeCompare(deviceKey, DEVICE_API_KEY)) {
        socket.isDevice = true;
        return next();
    }

    const token = socket.handshake.auth?.token;
    if (token && verifyToken(token)) {
        socket.userId = verifyToken(token).sub;
        return next();
    }

    next(new Error("Non autorizzato"));
});

io.on("connection", (socket) => {
    console.log(socket.isDevice ? `🔌 Device: ${socket.id}` : `🔌 Dashboard: ${socket.id}`);

    socket.on("register_device", (data) => {
        if (!socket.isDevice || !data?.deviceId) return;

        const existingEntry = Object.entries(devicesOnline).find(([, d]) => d.deviceId === data.deviceId);
        let existingSims = [];
        if (existingEntry) {
            existingSims = existingEntry[1].sims || [];
            delete devicesOnline[existingEntry[0]];
        }

        const device = { deviceId: data.deviceId, model: data.model || "unknown", phoneNumber: data.phoneNumber || "unknown", sims: existingSims, connectedAt: Date.now() };
        devicesOnline[socket.id] = device;

        (data.sims || []).forEach(incomingSim => {
            let sim = sims.find(s => s.deviceId === data.deviceId && s.simId === incomingSim.simId);
            if (!sim) {
                sim = { id: Date.now() + Math.random(), deviceId: data.deviceId, simId: incomingSim.simId, label: null, candidate: null, senders: [], lastSeen: Date.now() };
                sims.push(sim);
            }
            if (incomingSim.number?.trim()) sim.candidate = incomingSim.number.trim();
            sim.lastSeen = Date.now();
            if (!device.sims.find(s => s.simId === sim.simId)) device.sims.push({ simId: sim.simId, label: sim.label });
        });

        console.log(`📱 Device online | ${device.deviceId} | ${device.model}`);
    });

    socket.on("disconnect", () => {
        const device = devicesOnline[socket.id];
        if (device) { console.log("❌ Device offline:", device.deviceId); delete devicesOnline[socket.id]; }
    });
});

// ────────────────────────────────────────────
// 📩 SMS / TEST / SIM / DEVICES
// ────────────────────────────────────────────
app.post("/sms", authDevice, (req, res) => {
    const sms = req.body;
    if (!sms?.deviceId || !sms?.simId) return res.status(400).json({ error: "Campi obbligatori" });

    smsList.push({ ...sms, timestamp: sms.timestamp || Date.now() });

    let sim = sims.find(s => s.deviceId === sms.deviceId && s.simId === sms.simId);
    if (!sim) {
        sim = { id: Date.now() + Math.random(), deviceId: sms.deviceId, simId: sms.simId, label: null, candidate: null, senders: [], lastSeen: Date.now() };
        sims.push(sim);
    }
    sim.lastSeen = Date.now();
    if (sms.sender && !sim.senders.includes(sms.sender)) sim.senders.push(sms.sender);
    Object.values(devicesOnline).forEach(d => {
        if (d.deviceId === sms.deviceId && !d.sims.find(s => s.simId === sms.simId)) d.sims.push({ simId: sms.simId, label: null });
    });

    io.emit("new_sms", sms);

    tests.forEach(test => {
        if (test.status === "PENDING" && sms.deviceId === test.deviceId && sms.simId === test.simId &&
            sms.message?.toLowerCase().includes(test.expected.toLowerCase())) {
            test.status = "PASS"; test.result = sms.message; test.completedAt = Date.now();
            io.emit("test_update", test);
        }
    });

    res.json({ status: "ok" });
});

app.get("/sms",            requireAuth, (req, res) => res.json(smsList));
app.get("/sims",           requireAuth, (req, res) => res.json(sims));
app.get("/devices-online", requireAuth, (req, res) => res.json(Object.values(devicesOnline)));
app.get("/tests",          requireAuth, (req, res) => res.json(tests));

// ────────────────────────────────────────────
// 📊 STATS
// ────────────────────────────────────────────
app.get("/stats", requireAuth, (req, res) => {
    const now = Date.now();
    const w24  = now - 24 * 3600000;
    const w7d  = now - 7  * 24 * 3600000;

    const recent = tests.filter(t => t.createdAt > w24);
    const pass24 = recent.filter(t => t.status === "PASS").length;
    const fail24 = recent.filter(t => t.status === "FAIL").length;
    const total24 = recent.length;
    const deliveryRate = total24 > 0 ? Math.round(pass24 / total24 * 100) : null;

    const passWithTime = recent.filter(t => t.status === "PASS" && t.completedAt);
    const avgLatency = passWithTime.length > 0
        ? Math.round(passWithTime.reduce((a, t) => a + (t.completedAt - t.createdAt), 0) / passWithTime.length)
        : null;

    const prefixMap = {
        "+39":"IT","+44":"UK","+1":"US","+49":"DE","+33":"FR",
        "+34":"ES","+31":"NL","+48":"PL","+55":"BR","+91":"IN","+86":"CN","+7":"RU"
    };

    const countryStats = {};
    tests.filter(t => t.createdAt > w7d).forEach(test => {
        const sim = sims.find(s => s.deviceId === test.deviceId && s.simId === test.simId);
        const num = sim?.label || sim?.candidate || "";
        let country = "OTHER";
        for (const [prefix, code] of Object.entries(prefixMap)) {
            const bare = prefix.slice(1);
            if (num.startsWith(prefix) || num.startsWith(bare) || num.startsWith("00"+bare)) { country = code; break; }
        }
        if (!countryStats[country]) countryStats[country] = { pass:0, fail:0, latencies:[] };
        if (test.status === "PASS") { countryStats[country].pass++; if (test.completedAt) countryStats[country].latencies.push(test.completedAt - test.createdAt); }
        if (test.status === "FAIL") countryStats[country].fail++;
    });

    const byCountry = Object.entries(countryStats).map(([country, d]) => ({
        country, pass: d.pass, fail: d.fail, total: d.pass + d.fail,
        deliveryRate: d.pass + d.fail > 0 ? Math.round(d.pass / (d.pass + d.fail) * 100) : null,
        avgLatency:   d.latencies.length > 0 ? Math.round(d.latencies.reduce((a,b)=>a+b,0)/d.latencies.length) : null
    }));

    const hourly = Array.from({length: 24}, (_, i) => {
        const from = now - (24 - i) * 3600000;
        const to   = from + 3600000;
        const b = tests.filter(t => t.createdAt >= from && t.createdAt < to);
        return { hour: new Date(from).getHours(), pass: b.filter(t=>t.status==="PASS").length, fail: b.filter(t=>t.status==="FAIL").length };
    });

    res.json({
        summary: { total24, pass24, fail24, deliveryRate, avgLatency, totalSims: sims.length, onlineDevices: Object.keys(devicesOnline).length },
        byCountry, hourly
    });
});

// ────────────────────────────────────────────
// 🗓  SCHEDULES
// ────────────────────────────────────────────
let schedules    = [];
let scheduleJobs = {};

function startScheduleJob(schedule) {
    if (scheduleJobs[schedule.id]) clearInterval(scheduleJobs[schedule.id]);
    if (!schedule.enabled) return;

    const run = () => {
        if (!schedule.enabled) return;
        schedule.lastRun = Date.now();
        schedule.nextRun = Date.now() + schedule.intervalMs;
        const test = {
            id: Date.now(), expected: schedule.expected,
            deviceId: schedule.deviceId, simId: schedule.simId,
            status: "PENDING", createdAt: Date.now(), completedAt: null,
            result: null, timeout: 60000,
            createdBy: `⏱ ${schedule.name}`
        };
        tests.push(test);
        io.emit("new_test", test);
        console.log(`🗓 Schedule run: ${schedule.name}`);
    };

    scheduleJobs[schedule.id] = setInterval(run, schedule.intervalMs);
    schedule.nextRun = Date.now() + schedule.intervalMs;
}

app.get("/schedules",     requireAuth,  (req, res) => res.json(schedules));

app.post("/schedules", requireAdmin, (req, res) => {
    const { name, expected, deviceId, simId, intervalMinutes } = req.body;
    if (!name || !expected || !deviceId || !simId || !intervalMinutes)
        return res.status(400).json({ error: "Campi obbligatori mancanti" });

    const intervalMs = Math.max(5, parseInt(intervalMinutes)) * 60000;
    const schedule = {
        id: crypto.randomUUID(), name: name.trim(),
        expected: expected.trim(), deviceId, simId,
        intervalMs, intervalMinutes: parseInt(intervalMinutes),
        enabled: true, lastRun: null,
        nextRun: Date.now() + intervalMs,
        createdAt: Date.now(), createdBy: req.user.username
    };

    schedules.push(schedule);
    startScheduleJob(schedule);
    console.log(`🗓 Nuovo schedule: ${schedule.name} ogni ${intervalMinutes}m`);
    res.status(201).json(schedule);
});

app.patch("/schedules/:id", requireAdmin, (req, res) => {
    const s = schedules.find(s => s.id === req.params.id);
    if (!s) return res.status(404).json({ error: "Non trovato" });

    if (req.body.enabled !== undefined) {
        s.enabled = Boolean(req.body.enabled);
        if (s.enabled) startScheduleJob(s);
        else { clearInterval(scheduleJobs[s.id]); delete scheduleJobs[s.id]; }
    }
    res.json(s);
});

app.delete("/schedules/:id", requireAdmin, (req, res) => {
    const idx = schedules.findIndex(s => s.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "Non trovato" });
    clearInterval(scheduleJobs[schedules[idx].id]);
    delete scheduleJobs[schedules[idx].id];
    schedules.splice(idx, 1);
    res.json({ ok: true });
});

app.post("/test", requireAuth, (req, res) => {
    const { expected, deviceId, simId } = req.body;
    if (!expected || !deviceId || !simId) return res.status(400).json({ error: "Campi obbligatori" });

    const test = { id: Date.now(), expected: expected.trim(), deviceId, simId, status: "PENDING", createdAt: Date.now(), completedAt: null, result: null, timeout: 30000, createdBy: req.user.username };
    tests.push(test);
    res.json(test);
});

app.post("/set-sim-label", requireAuth, (req, res) => {
    const { deviceId, simId, label } = req.body;
    if (!deviceId || !simId) return res.status(400).json({ error: "Campi obbligatori" });

    const sim = sims.find(s => s.deviceId === deviceId && s.simId === simId);
    if (!sim) return res.status(404).json({ error: "SIM non trovata" });

    sim.label = label?.trim() || null;
    sim.candidate = null;
    res.json({ ok: true });
});

// ────────────────────────────────────────────
// ⏱  TIMEOUT TEST
// ────────────────────────────────────────────
setInterval(() => {
    const now = Date.now();
    tests.forEach(test => {
        if (test.status === "PENDING" && now - test.createdAt > test.timeout) {
            test.status = "FAIL"; test.completedAt = Date.now();
            io.emit("test_update", test);
        }
    });
}, 5000);

setInterval(() => {
    const now = Date.now();
    sessions = sessions.filter(s => s.expiresAt > now || !s.revoked);
}, 3600000);

// ────────────────────────────────────────────
// 🚀 START
// ────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
seedAdmin().then(() => {
    server.listen(PORT, () => {
        console.log(`🚀 Server su porta ${PORT}`);
        console.log(`📱 DEVICE_API_KEY: ${DEVICE_API_KEY}`);
    });
});