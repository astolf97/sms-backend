const express  = require("express");
const cors     = require("cors");
const path     = require("path");
const http     = require("http");
const crypto   = require("crypto");
const bcrypt   = require("bcryptjs");
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
const BCRYPT_ROUNDS       = 10;
const APP_JWT_EXPIRES_IN  = "30d";   // app stays logged in longer

if (!process.env.JWT_SECRET) {
    console.warn("⚠️  JWT_SECRET non impostato — i token saranno invalidati al riavvio.");
}

// ────────────────────────────────────────────
// 🗄  STORAGE (in-memory)
// ────────────────────────────────────────────
let users         = [];   // dashboard users
let sessions      = [];
let devicesOnline = {};
let smsList       = [];
let tests         = [];
let sims          = [];

// ── App users (device owners — separate from dashboard users)
let appUsers      = [];   // { id, username, passwordHash, createdAt, deviceIds[] }
let appSessions   = [];   // { token, appUserId, createdAt, expiresAt }
let deviceMeta    = {};   // deviceId → { nickname, appUserId, createdAt }

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
// 📱 APP AUTH HELPERS
// ────────────────────────────────────────────
function signAppToken(appUser) {
    return jwt.sign(
        { sub: appUser.id, username: appUser.username, type: "app" },
        JWT_SECRET,
        { expiresIn: APP_JWT_EXPIRES_IN }
    );
}

function requireAppAuth(req, res, next) {
    const auth = req.headers.authorization;
    const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Token mancante" });

    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); }
    catch { return res.status(401).json({ error: "Token scaduto o non valido" }); }

    if (payload.type !== "app") return res.status(401).json({ error: "Token non valido per app" });

    const revoked = appSessions.find(s => s.token === token && s.revoked);
    if (revoked) return res.status(401).json({ error: "Sessione revocata" });

    const appUser = appUsers.find(u => u.id === payload.sub);
    if (!appUser) return res.status(401).json({ error: "Utente app non trovato" });

    req.appUser = appUser;
    req.appToken = token;
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
    // Device app → API key
    const deviceKey = socket.handshake.auth?.apiKey;
    if (deviceKey && safeCompare(deviceKey, DEVICE_API_KEY)) {
        socket.isDevice = true;

        // If app user token also provided, bind device to user
        const appToken = socket.handshake.auth?.appToken;
        if (appToken) {
            try {
                const payload = jwt.verify(appToken, JWT_SECRET);
                if (payload.type === "app") socket.appUserId = payload.sub;
            } catch {}
        }
        return next();
    }

    // Dashboard → JWT
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

        const device = {
            deviceId:    data.deviceId,
            model:       data.model || "unknown",
            phoneNumber: data.phoneNumber || "unknown",
            sims:        existingSims,
            connectedAt: Date.now(),
            appUserId:   socket.appUserId || null
        };
        devicesOnline[socket.id] = device;

        // Init device metadata
        if (!deviceMeta[data.deviceId]) {
            deviceMeta[data.deviceId] = { nickname: null, model: data.model || "unknown", createdAt: Date.now() };
        }
        deviceMeta[data.deviceId].model = data.model || deviceMeta[data.deviceId].model;

        // Bind device to app user
        if (socket.appUserId) {
            const appUser = appUsers.find(u => u.id === socket.appUserId);
            if (appUser && !appUser.deviceIds.includes(data.deviceId)) {
                appUser.deviceIds.push(data.deviceId);
                console.log(`🔗 Device ${data.deviceId} legato a app user: ${appUser.username}`);
            }
        }

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

        console.log(`📱 Device online | ${device.deviceId} | ${device.model} | user: ${socket.appUserId || "anonimo"}`);
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

app.get("/sms", requireAuth, (req, res) => {
    if (req.user.role === "admin") return res.json(smsList);

    // user: redact phone numbers — show only country code
    const prefixMap = {
        "+39":"🇮🇹 IT","+44":"🇬🇧 UK","+1":"🇺🇸 US","+49":"🇩🇪 DE","+33":"🇫🇷 FR",
        "+34":"🇪🇸 ES","+31":"🇳🇱 NL","+48":"🇵🇱 PL","+55":"🇧🇷 BR","+91":"🇮🇳 IN",
        "+86":"🇨🇳 CN","+7":"🇷🇺 RU"
    };

    function redactSender(sender) {
        if (!sender) return "—";
        for (const [prefix] of Object.entries(prefixMap)) {
            const bare = prefix.slice(1);
            if (sender.startsWith(prefix) || sender.startsWith(bare) || sender.startsWith("00"+bare)) {
                return prefixMap[prefix];
            }
        }
        return "🌍 INTL";
    }

    res.json(smsList.map(s => ({ ...s, sender: redactSender(s.sender) })));
});

app.get("/sims", requireAuth, (req, res) => {
    if (req.user.role === "admin") return res.json(sims);

    // user: show country only, no numbers, no deviceId detail
    const prefixMap = {
        "+39":"🇮🇹 IT","+44":"🇬🇧 UK","+1":"🇺🇸 US","+49":"🇩🇪 DE","+33":"🇫🇷 FR",
        "+34":"🇪🇸 ES","+31":"🇳🇱 NL","+48":"🇵🇱 PL","+55":"🇧🇷 BR","+91":"🇮🇳 IN",
        "+86":"🇨🇳 CN","+7":"🇷🇺 RU"
    };

    function getCountry(num) {
        if (!num) return null;
        for (const [prefix, label] of Object.entries(prefixMap)) {
            const bare = prefix.slice(1);
            if (num.startsWith(prefix) || num.startsWith(bare) || num.startsWith("00"+bare)) return label;
        }
        return "🌍 INTL";
    }

    // group by country — count only
    const countryCount = {};
    sims.forEach(sim => {
        const num     = sim.label || sim.candidate || "";
        const country = getCountry(num) || "❓ Sconosciuto";
        if (!countryCount[country]) countryCount[country] = { country, count: 0, simId: `country-${country}`, deviceId: "—", label: country, candidate: null };
        countryCount[country].count++;
    });

    res.json(Object.values(countryCount).map(c => ({
        simId:    c.simId,
        deviceId: "—",
        label:    `${c.country} (${c.count} SIM)`,
        candidate: null,
        isRedacted: true
    })));
});

app.get("/devices-online", requireAuth, (req, res) => {
    if (req.user.role === "admin") {
        // Enrich each device with nickname from deviceMeta
        const enriched = Object.values(devicesOnline).map(d => ({
            ...d,
            nickname: deviceMeta[d.deviceId]?.nickname || null,
            appUserId: deviceMeta[d.deviceId]?.appUserId || d.appUserId || null
        }));
        return res.json(enriched);
    }

    // user: count only per country, no deviceId/model/numbers
    const prefixMap = {
        "+39":"🇮🇹 IT","+44":"🇬🇧 UK","+1":"🇺🇸 US","+49":"🇩🇪 DE","+33":"🇫🇷 FR",
        "+34":"🇪🇸 ES","+31":"🇳🇱 NL","+48":"🇵🇱 PL","+55":"🇧🇷 BR","+91":"🇮🇳 IN",
        "+86":"🇨🇳 CN","+7":"🇷🇺 RU"
    };

    function getCountry(num) {
        for (const [prefix, label] of Object.entries(prefixMap)) {
            const bare = prefix.slice(1);
            if (num.startsWith(prefix) || num.startsWith(bare) || num.startsWith("00"+bare)) return label;
        }
        return "🌍 INTL";
    }

    const countryMap = {};
    Object.values(devicesOnline).forEach(device => {
        (device.sims || []).forEach(sim => {
            const cached = sims.find(s => s.deviceId === device.deviceId && s.simId === sim.simId);
            const num    = cached?.label || cached?.candidate || "";
            const ctry   = getCountry(num) || "❓";
            if (!countryMap[ctry]) countryMap[ctry] = { country: ctry, devices: 0, sims: 0 };
            countryMap[ctry].sims++;
        });
        // count unique devices per country (simplified: 1 per device)
        const deviceCountries = new Set();
        (device.sims || []).forEach(sim => {
            const cached = sims.find(s => s.deviceId === device.deviceId && s.simId === sim.simId);
            const num    = cached?.label || cached?.candidate || "";
            deviceCountries.add(getCountry(num) || "❓");
        });
        deviceCountries.forEach(c => {
            if (!countryMap[c]) countryMap[c] = { country: c, devices: 0, sims: 0 };
            countryMap[c].devices++;
        });
    });

    res.json({ redacted: true, summary: Object.values(countryMap), total: Object.keys(devicesOnline).length });
});

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
// 📱 APP AUTH ENDPOINTS
// ────────────────────────────────────────────

// Register new app user
app.post("/app/register", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)   return res.status(400).json({ error: "Username e password obbligatori" });
    if (username.trim().length < 3) return res.status(400).json({ error: "Username minimo 3 caratteri" });
    if (password.length < 6)      return res.status(400).json({ error: "Password minimo 6 caratteri" });
    if (appUsers.find(u => u.username === username.trim())) {
        return res.status(409).json({ error: "Username già in uso" });
    }

    const appUser = {
        id:           crypto.randomUUID(),
        username:     username.trim(),
        passwordHash: await bcrypt.hash(password, BCRYPT_ROUNDS),
        createdAt:    Date.now(),
        deviceIds:    []
    };

    appUsers.push(appUser);
    console.log(`📱 Nuovo app user: ${appUser.username}`);

    const token = signAppToken(appUser);
    appSessions.push({ token, appUserId: appUser.id, createdAt: Date.now(), expiresAt: Date.now() + 30 * 24 * 3600000, revoked: false });

    res.status(201).json({ token, user: { id: appUser.id, username: appUser.username } });
});

// Login app user
app.post("/app/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Campi obbligatori" });

    const appUser = appUsers.find(u => u.username === username.trim());
    const dummy   = "$2b$10$dummyhashfortimingreasonxxxxx.xx";
    const valid   = appUser
        ? await bcrypt.compare(password, appUser.passwordHash)
        : (await bcrypt.compare(password, dummy), false);

    if (!valid || !appUser) return res.status(401).json({ error: "Credenziali non valide" });

    const token = signAppToken(appUser);
    appSessions.push({ token, appUserId: appUser.id, createdAt: Date.now(), expiresAt: Date.now() + 30 * 24 * 3600000, revoked: false });

    console.log(`📱 App login: ${appUser.username}`);
    res.json({ token, user: { id: appUser.id, username: appUser.username, deviceIds: appUser.deviceIds } });
});

// Logout app user
app.post("/app/logout", requireAppAuth, (req, res) => {
    const s = appSessions.find(s => s.token === req.appToken);
    if (s) s.revoked = true;
    res.json({ ok: true });
});

// Get current app user info + their devices
app.get("/app/me", requireAppAuth, (req, res) => {
    const myDevices = req.appUser.deviceIds.map(dId => {
        const meta   = deviceMeta[dId] || {};
        const online = Object.values(devicesOnline).find(d => d.deviceId === dId);
        const mySims = sims.filter(s => s.deviceId === dId).map(s => ({
            simId: s.simId,
            label: s.label,
            candidate: s.candidate
        }));
        return {
            deviceId:  dId,
            nickname:  meta.nickname || dId,
            online:    !!online,
            model:     online?.model || meta.model || "unknown",
            sims:      mySims
        };
    });

    res.json({
        id:        req.appUser.id,
        username:  req.appUser.username,
        devices:   myDevices
    });
});

// Rename device — app user (owner only)
app.patch("/app/device/:deviceId/rename", requireAppAuth, (req, res) => {
    const { deviceId } = req.params;
    const { nickname }  = req.body;

    if (!req.appUser.deviceIds.includes(deviceId)) {
        return res.status(403).json({ error: "Non sei il proprietario di questo device" });
    }

    if (!nickname?.trim()) return res.status(400).json({ error: "Nickname obbligatorio" });

    if (!deviceMeta[deviceId]) deviceMeta[deviceId] = {};
    deviceMeta[deviceId].nickname = nickname.trim();

    // Emit realtime update to dashboard
    io.emit("device_renamed", { deviceId, nickname: nickname.trim() });

    console.log(`✏️  Device rinominato (app): ${deviceId} → ${nickname.trim()}`);
    res.json({ ok: true, nickname: nickname.trim() });
});

// Rename device — dashboard admin
app.patch("/device/:deviceId/rename", requireAdmin, (req, res) => {
    const { deviceId } = req.params;
    const { nickname }  = req.body;

    if (!nickname?.trim()) return res.status(400).json({ error: "Nickname obbligatorio" });

    if (!deviceMeta[deviceId]) deviceMeta[deviceId] = {};
    deviceMeta[deviceId].nickname = nickname.trim();

    io.emit("device_renamed", { deviceId, nickname: nickname.trim() });

    console.log(`✏️  Device rinominato (dashboard): ${deviceId} → ${nickname.trim()}`);
    res.json({ ok: true, nickname: nickname.trim() });
});

// Get SMS for this app user (only their devices)
app.get("/app/sms", requireAppAuth, (req, res) => {
    const myDeviceIds = req.appUser.deviceIds;
    const mySms = smsList
        .filter(s => myDeviceIds.includes(s.deviceId))
        .slice(-500); // last 500
    res.json(mySms);
});

// Get SIMs for this app user
app.get("/app/sims", requireAppAuth, (req, res) => {
    const myDeviceIds = req.appUser.deviceIds;
    res.json(sims.filter(s => myDeviceIds.includes(s.deviceId)));
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