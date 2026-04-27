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

    console.log("Client connesso");

    socket.on("register_device", (data) => {

        devicesOnline[socket.id] = {
            deviceId: data.deviceId,
            model: data.model,
            phoneNumber: data.phoneNumber,
            connectedAt: Date.now()
        };

        console.log("📱 Device online:", data.deviceId);
    });

    socket.on("disconnect", () => {

        delete devicesOnline[socket.id];

        console.log("Client disconnesso");
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
    // 🔥 AUTO-DETECT SIM (core del sistema)
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
    // 🔥 REALTIME
    //
    io.emit("new_sms", sms);

    //
    // 🧪 MATCH TEST (FIX IMPORTANTE)
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
        deviceId: req.body.deviceId,   // 🔥 IMPORTANTE
        simId: req.body.simId,         // 🔥 IMPORTANTE
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
            }
        }
    });

}, 5000);

//
// 📶 LISTA SIM REALI
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