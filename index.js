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

let devicesOnline = {};

io.on("connection", (socket) => {

    console.log("Client connesso");

    socket.on("register_device", (data) => {

        devicesOnline[socket.id] = data; // salva tutto

        console.log("Device online:", data);
    });

    socket.on("disconnect", () => {

        delete devicesOnline[socket.id];

        console.log("Client disconnesso");
    });
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

let smsList = [];
let tests = [];
let sims = [];

// 📩 SMS
app.post("/sms", (req, res) => {

    const sms = req.body; // ✅ PRIMA

    smsList.push(sms);

    console.log("SMS ricevuto:", sms);

    // 🔥 REALTIME
    io.emit("new_sms", sms);

    // 🔥 MATCH TEST
    tests.forEach(test => {
        if (test.status === "PENDING") {
            if (sms.simId === test.simId) {
                if (sms.message.toLowerCase().includes(test.expected.toLowerCase())) {
                    test.status = "PASS";
                    test.result = sms.message;
                    test.completedAt = Date.now();
                }
            }
        }
    });

    res.json({ status: "ok" });
});

// 📥 SMS
app.get("/sms", (req, res) => {
    res.json(smsList);
});

// 🧪 TEST
app.post("/test", (req, res) => {
    const test = {
        id: Date.now(),
        expected: req.body.expected,
        simId: req.body.simId,
        status: "PENDING",
        createdAt: Date.now(),
        completedAt: null,
        timeout: 30000
    };

    tests.push(test);
    res.json(test);
});

app.get("/tests", (req, res) => {
    res.json(tests);
});

// ⏱ timeout
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

// 📶 SIM
app.post("/register-sim", (req, res) => {
    const sim = {
        id: Date.now(),
        deviceId: req.body.deviceId,
        simId: req.body.simId,
        phoneNumber: req.body.phoneNumber
    };

    sims.push(sim);

    console.log("SIM registrata:", sim);

    res.json(sim);
});

app.get("/sims", (req, res) => {
    res.json(sims);
});


app.get("/devices-online", (req, res) => {
    res.json(Object.values(devicesOnline));
});


const PORT = process.env.PORT || 3000;

// ❗ QUI STA LA DIFFERENZA
server.listen(PORT, () => {
    console.log("Server (WebSocket) avviato su porta", PORT);
});