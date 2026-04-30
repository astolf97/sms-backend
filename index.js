const express = require("express");
const cors    = require("cors");
const path    = require("path");
const http    = require("http");
const crypto  = require("crypto");
const { Server } = require("socket.io");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

// ────────────────────────────────────────────
// 🔑 CONFIGURAZIONE AUTH
//
//  Imposta la tua API key in una variabile d'ambiente:
//      export DASHBOARD_API_KEY="la-tua-chiave-segreta"
//
//  Se non impostata, viene generata automaticamente ad ogni avvio
//  e stampata in console — cambiala in produzione!
// ────────────────────────────────────────────
const DASHBOARD_API_KEY = process.env.DASHBOARD_API_KEY || (() => {
    const generated = crypto.randomBytes(24).toString("hex");
    console.log("⚠️  DASHBOARD_API_KEY non impostata. Chiave generata per questa sessione:");
    console.log(`    ${generated}`);
    console.log("    Impostala come variabile d'ambiente per renderla persistente.");
    return generated;
})();

// Chiave per le app Android che inviano SMS (può essere uguale o diversa)
const DEVICE_API_KEY = process.env.DEVICE_API_KEY || DASHBOARD_API_KEY;

// ────────────────────────────────────────────
// 🗄  STORAGE (in-memory)
// ────────────────────────────────────────────
let devicesOnline = {};
let smsList       = [];
let tests         = [];
let sims          = [];

// ────────────────────────────────────────────
// 🛡  MIDDLEWARE DI AUTENTICAZIONE
// ────────────────────────────────────────────

/**
 * Confronto timing-safe per prevenire timing attacks
 */
function safeCompare(a, b) {
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

/**
 * Middleware: protegge gli endpoint della dashboard
 * Accetta la chiave via header X-API-Key o query ?api_key=
 */
function authDashboard(req, res, next) {
    const key = req.headers["x-api-key"] || req.query.api_key;

    if (!key || !safeCompare(key, DASHBOARD_API_KEY)) {
        return res.status(401).json({ error: "Non autorizzato" });
    }

    next();
}

/**
 * Middleware: protegge gli endpoint dei device (invio SMS)
 * Può usare una chiave separata (DEVICE_API_KEY)
 */
function authDevice(req, res, next) {
    const key = req.headers["x-api-key"] || req.query.api_key;

    if (!key || !safeCompare(key, DEVICE_API_KEY)) {
        return res.status(401).json({ error: "Non autorizzato" });
    }

    next();
}

// ────────────────────────────────────────────
// ⚙️  MIDDLEWARE GLOBALE
// ────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ────────────────────────────────────────────
// 🌐 STATIC + ROOT (pubblici — servono la dashboard)
// ────────────────────────────────────────────
app.use(express.static(__dirname));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// ────────────────────────────────────────────
// 🔐 AUTH: VERIFY (usato dal frontend per validare la chiave)
// ────────────────────────────────────────────
app.post("/auth/verify", authDashboard, (req, res) => {
    res.json({ ok: true });
});

// ────────────────────────────────────────────
// 🔌 SOCKET.IO
//    I device si autenticano inviando la chiave nel handshake
// ────────────────────────────────────────────
io.use((socket, next) => {
    const key = socket.handshake.auth?.apiKey || socket.handshake.query?.api_key;

    if (!key || !safeCompare(key, DEVICE_API_KEY)) {
        console.warn("🚫 Socket rifiutato — chiave non valida");
        return next(new Error("Non autorizzato"));
    }

    next();
});

io.on("connection", (socket) => {
    console.log("🔌 Device connesso:", socket.id);

    socket.on("register_device", (data) => {
        if (!data?.deviceId) return;

        // Se il device si riconnette, recupera le SIM già note
        const existingEntry = Object.entries(devicesOnline)
            .find(([, d]) => d.deviceId === data.deviceId);

        let existingSims = [];
        if (existingEntry) {
            const [oldSocketId, oldDevice] = existingEntry;
            existingSims = oldDevice.sims || [];
            delete devicesOnline[oldSocketId];
        }

        const device = {
            deviceId:    data.deviceId,
            model:       data.model       || "unknown",
            phoneNumber: data.phoneNumber || "unknown",
            sims:        existingSims,
            connectedAt: Date.now()
        };

        devicesOnline[socket.id] = device;

        // Aggiorna / crea SIM dalla registrazione
        (data.sims || []).forEach(incomingSim => {
            let sim = sims.find(
                s => s.deviceId === data.deviceId && s.simId === incomingSim.simId
            );

            if (!sim) {
                sim = {
                    id:        Date.now() + Math.random(),
                    deviceId:  data.deviceId,
                    simId:     incomingSim.simId,
                    label:     null,
                    candidate: null,
                    senders:   [],
                    lastSeen:  Date.now()
                };
                sims.push(sim);
                console.log("🔥 Nuova SIM da register:", sim.simId);
            }

            if (incomingSim.number?.trim()) {
                sim.candidate = incomingSim.number.trim();
                console.log("🟡 Candidate aggiornato:", sim.simId, sim.candidate);
            }

            sim.lastSeen = Date.now();

            const alreadyInDevice = device.sims.find(s => s.simId === sim.simId);
            if (!alreadyInDevice) {
                device.sims.push({ simId: sim.simId, label: sim.label });
            }
        });

        console.log(`📱 Device online | id=${device.deviceId} | model=${device.model} | sims=${device.sims.length}`);
    });

    socket.on("disconnect", () => {
        const device = devicesOnline[socket.id];
        console.log(device
            ? `❌ Device offline: ${device.deviceId}`
            : `❌ Socket disconnesso: ${socket.id}`
        );
        delete devicesOnline[socket.id];
    });
});

// ────────────────────────────────────────────
// 📩 RICEZIONE SMS  [protetto — device key]
// ────────────────────────────────────────────
app.post("/sms", authDevice, (req, res) => {
    const sms = req.body;

    if (!sms?.deviceId || !sms?.simId) {
        return res.status(400).json({ error: "deviceId e simId sono obbligatori" });
    }

    smsList.push({ ...sms, timestamp: sms.timestamp || Date.now() });
    console.log("📩 SMS ricevuto:", sms.deviceId, sms.simId, sms.sender);

    // Trova o crea SIM
    let sim = sims.find(s => s.deviceId === sms.deviceId && s.simId === sms.simId);
    if (!sim) {
        sim = {
            id:        Date.now() + Math.random(),
            deviceId:  sms.deviceId,
            simId:     sms.simId,
            label:     null,
            candidate: null,
            senders:   [],
            lastSeen:  Date.now()
        };
        sims.push(sim);
        console.log("🔥 Nuova SIM rilevata via SMS:", sim.simId);
    }

    sim.lastSeen = Date.now();
    if (sms.sender && !sim.senders.includes(sms.sender)) {
        sim.senders.push(sms.sender);
    }

    // Aggiungi SIM al device online se mancante
    Object.values(devicesOnline).forEach(d => {
        if (d.deviceId === sms.deviceId && !d.sims.find(s => s.simId === sms.simId)) {
            d.sims.push({ simId: sms.simId, label: null });
        }
    });

    io.emit("new_sms", sms);

    // Controlla test pendenti
    tests.forEach(test => {
        if (
            test.status   === "PENDING"    &&
            sms.deviceId  === test.deviceId &&
            sms.simId     === test.simId    &&
            sms.message?.toLowerCase().includes(test.expected.toLowerCase())
        ) {
            test.status      = "PASS";
            test.result      = sms.message;
            test.completedAt = Date.now();
            console.log("✅ TEST PASS:", test.id);
            io.emit("test_update", test);
        }
    });

    res.json({ status: "ok" });
});

// ────────────────────────────────────────────
// 📥 LISTA SMS  [protetto — dashboard]
// ────────────────────────────────────────────
app.get("/sms", authDashboard, (req, res) => {
    res.json(smsList);
});

// ────────────────────────────────────────────
// 🧪 CREA TEST  [protetto — dashboard]
// ────────────────────────────────────────────
app.post("/test", authDashboard, (req, res) => {
    const { expected, deviceId, simId } = req.body;

    if (!expected || !deviceId || !simId) {
        return res.status(400).json({ error: "expected, deviceId e simId sono obbligatori" });
    }

    const test = {
        id:          Date.now(),
        expected:    expected.trim(),
        deviceId,
        simId,
        status:      "PENDING",
        createdAt:   Date.now(),
        completedAt: null,
        result:      null,
        timeout:     30000
    };

    tests.push(test);
    console.log("🧪 Nuovo test:", test.id, test.expected);
    res.json(test);
});

// ────────────────────────────────────────────
// 📊 LISTA TEST  [protetto — dashboard]
// ────────────────────────────────────────────
app.get("/tests", authDashboard, (req, res) => {
    res.json(tests);
});

// ────────────────────────────────────────────
// 🏷  SET SIM LABEL  [protetto — dashboard]
// ────────────────────────────────────────────
app.post("/set-sim-label", authDashboard, (req, res) => {
    const { deviceId, simId, label } = req.body;

    if (!deviceId || !simId) {
        return res.status(400).json({ error: "deviceId e simId sono obbligatori" });
    }

    const sim = sims.find(s => s.deviceId === deviceId && s.simId === simId);
    if (!sim) return res.status(404).json({ error: "SIM non trovata" });

    sim.label     = label?.trim() || null;
    sim.candidate = null;

    console.log("🏷  Label impostata:", simId, sim.label);
    res.json({ ok: true });
});

// ────────────────────────────────────────────
// 📶 LISTA SIM  [protetto — dashboard]
// ────────────────────────────────────────────
app.get("/sims", authDashboard, (req, res) => {
    res.json(sims);
});

// ────────────────────────────────────────────
// 📱 DEVICE ONLINE  [protetto — dashboard]
// ────────────────────────────────────────────
app.get("/devices-online", authDashboard, (req, res) => {
    res.json(Object.values(devicesOnline));
});

// ────────────────────────────────────────────
// ⏱  TIMEOUT TEST
// ────────────────────────────────────────────
setInterval(() => {
    const now = Date.now();
    tests.forEach(test => {
        if (test.status === "PENDING" && now - test.createdAt > test.timeout) {
            test.status      = "FAIL";
            test.completedAt = Date.now();
            console.log("❌ TEST FAIL (timeout):", test.id);
            io.emit("test_update", test);
        }
    });
}, 5000);

// ────────────────────────────────────────────
// 🚀 START
// ────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server avviato su porta ${PORT}`);
});
