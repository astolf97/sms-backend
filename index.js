const express = require("express");
const cors    = require("cors");
const path    = require("path");
const http    = require("http");
const { Server } = require("socket.io");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

// ────────────────────────────────────────────
// 🗄  STORAGE (in-memory)
// ────────────────────────────────────────────
let devicesOnline = {};  // socketId → device
let smsList       = [];
let tests         = [];
let sims          = [];

// ────────────────────────────────────────────
// 🔌 SOCKET.IO
// ────────────────────────────────────────────
io.on("connection", (socket) => {
    console.log("🔌 Client connesso:", socket.id);

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

            // Il numero arrivato dall'app diventa "candidate" (da confermare)
            if (incomingSim.number?.trim()) {
                sim.candidate = incomingSim.number.trim();
                console.log("🟡 Candidate aggiornato:", sim.simId, sim.candidate);
            }

            sim.lastSeen = Date.now();

            // Aggiungi la SIM alla lista sims del device se non presente
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
            : `❌ Client disconnesso: ${socket.id}`
        );
        delete devicesOnline[socket.id];
    });
});

// ────────────────────────────────────────────
// ⚙️  MIDDLEWARE
// ────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ────────────────────────────────────────────
// 🌐 ROOT
// ────────────────────────────────────────────
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// ────────────────────────────────────────────
// 📩 RICEZIONE SMS
// ────────────────────────────────────────────
app.post("/sms", (req, res) => {
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
            console.log("📶 SIM aggiunta al device online:", sms.simId);
        }
    });

    // Realtime push
    io.emit("new_sms", sms);

    // Controlla test pendenti
    tests.forEach(test => {
        if (
            test.status === "PENDING" &&
            sms.deviceId === test.deviceId &&
            sms.simId    === test.simId   &&
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
// 📥 LISTA SMS
// ────────────────────────────────────────────
app.get("/sms", (req, res) => {
    res.json(smsList);
});

// ────────────────────────────────────────────
// 🧪 CREA TEST
// ────────────────────────────────────────────
app.post("/test", (req, res) => {
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
// 📊 LISTA TEST
// ────────────────────────────────────────────
app.get("/tests", (req, res) => {
    res.json(tests);
});

// ────────────────────────────────────────────
// 🏷  SET SIM LABEL
// ────────────────────────────────────────────
app.post("/set-sim-label", (req, res) => {
    const { deviceId, simId, label } = req.body;

    if (!deviceId || !simId) {
        return res.status(400).json({ error: "deviceId e simId sono obbligatori" });
    }

    const sim = sims.find(s => s.deviceId === deviceId && s.simId === simId);
    if (!sim) {
        return res.status(404).json({ error: "SIM non trovata" });
    }

    sim.label     = label?.trim() || null;
    sim.candidate = null; // la label confermata sostituisce il candidate

    console.log("🏷  Label impostata:", simId, sim.label);
    res.json({ ok: true });
});

// ────────────────────────────────────────────
// 📶 LISTA SIM
// ────────────────────────────────────────────
app.get("/sims", (req, res) => {
    res.json(sims);
});

// ────────────────────────────────────────────
// 📱 DEVICE ONLINE
// ────────────────────────────────────────────
app.get("/devices-online", (req, res) => {
    res.json(Object.values(devicesOnline));
});

// ────────────────────────────────────────────
// ⏱  TIMEOUT TEST (controlla ogni 5 secondi)
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
