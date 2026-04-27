const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

const http = require("http");
const { Server } = require("socket.io");

const server = http.createServer(app);

const io = new Server(server, {
    cors: { origin: "*" }
});

//
// 🔥 STORAGE (in memoria)
//
let devicesOnline = {};
let smsList = [];
let tests = [];
let sims = [];

//
// 🔌 SOCKET.IO
//
io.on("connection", (socket) => {

    console.log("🔌 Client connesso:", socket.id);

    socket.on("register_device", (data) => {

        // 🔥 trova device già esistente (stesso deviceId)
        const existingEntry = Object.entries(devicesOnline).find(
            ([_, d]) => d.deviceId === data.deviceId
        );

        const device = {
            deviceId: data.deviceId,
            model: data.model || "unknown",
            phoneNumber: data.phoneNumber || "unknown",
            sims: data.sims || [],
            connectedAt: Date.now(),
            socketId: socket.id
        };

        // 🔥 se già esiste → rimuovi vecchio socket
        if (existingEntry) {
            const [oldSocketId] = existingEntry;
            delete devicesOnline[oldSocketId];
        }

        devicesOnline[socket.id] = device;

        // 🔥 LOG COMPLETO
        console.log("📱 DEVICE ONLINE");
        console.log("ID:", device.deviceId);
        console.log("MODEL:", device.model);
        console.log("PHONE:", device.phoneNumber);
        console.log("SIMS:", device.sims);
    });

    socket.on("disconnect", () => {

        const device = devicesOnline[socket.id];

        if (device) {
            console.log("❌ Device offline:", device.deviceId);
        } else {
            console.log("❌ Client disconnesso:", socket.id);
        }

        delete devicesOnline[socket.id];
    });
});

//
// ⚙️ MIDDLEWARE
//
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

//
// 🌐 ROOT
//
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

//
// 📩 RICEZIONE SMS
//
app.post("/sms", (req, res) => {

    const sms = req.body;

    smsList.push(sms);

    console.log("📩 SMS ricevuto:", sms);

    //
    // 🔥 AUTO-DETECT SIM (vera logica)
    //
    let sim = sims.find(
        s =>
            s.deviceId === sms.deviceId &&
            s.simId === sms.simId
    );

    if (!sim) {

        sim = {
            id: Date.now(),
            deviceId: sms.deviceId,
            simId: sms.simId,
            phoneNumber: sms.sender || "unknown",
            lastSeen: Date.now()
        };

        sims.push(sim);

        console.log("🔥 Nuova SIM rilevata:", sim);
    } else {
        sim.lastSeen = Date.now();
    }

    //
    // 🔥 aggiorna anche device ONLINE con questa SIM
    //
    Object.values(devicesOnline).forEach(d => {
        if (d.deviceId === sms.deviceId) {

            const exists = d.sims.find(s => s.simId === sms.simId);

            if (!exists) {
                d.sims.push({
                    simId: sms.simId,
                    phoneNumber: sms.sender || "unknown"
                });

                console.log("📶 SIM aggiunta al device:", sms.simId);
            }
        }
    });

    //
    // 🔥 REALTIME
    //
    io.emit("new_sms", sms);

    //
    // 🧪 MATCH TEST
    //
    tests.forEach(test => {
        if (test.status === "PENDING") {

            if (
                sms.deviceId === test.deviceId &&
                sms.simId === test.simId
            ) {
                if (
                    sms.message &&
                    sms.message.toLowerCase().includes(test.expected.toLowerCase())
                ) {
                    test.status = "PASS";
                    test.result = sms.message;
                    test.completedAt = Date.now();

                    console.log("✅ TEST PASS:", test.id);
                }
            }
        }
    });

    res.json({ status: "ok" });
});

//
// 📥 LISTA SMS
//
app.get("/sms", (req, res) => {
    res.json(smsList);
});

//
// 🧪 CREA TEST
//
app.post("/test", (req, res) => {

    const test = {
        id: Date.now(),
        expected: req.body.expected,
        deviceId: req.body.deviceId,
        simId: req.body.simId,
        status: "PENDING",
        createdAt: Date.now(),
        completedAt: null,
        timeout: 30000
    };

    tests.push(test);

    console.log("🧪 Nuovo test:", test);

    res.json(test);
});

//
// 📊 LISTA TEST
//
app.get("/tests", (req, res) => {
    res.json(tests);
});

//
// ⏱ TIMEOUT TEST
//
setInterval(() => {

    const now = Date.now();

    tests.forEach(test => {
        if (test.status === "PENDING") {
            if (now - test.createdAt > test.timeout) {
                test.status = "FAIL";
                test.completedAt = Date.now();

                console.log("❌ TEST FAIL:", test.id);
            }
        }
    });

}, 5000);

//
// 📶 LISTA SIM
//
app.get("/sims", (req, res) => {
    res.json(sims);
});

//
// 📱 DEVICE ONLINE
//
app.get("/devices-online", (req, res) => {
    res.json(Object.values(devicesOnline));
});

//
// 🚀 START SERVER
//
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log("🚀 Server avviato su porta", PORT);
});