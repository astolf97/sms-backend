const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

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
    const sms = req.body;
    smsList.push(sms);

    console.log("SMS ricevuto:", sms);

    // 🔥 MATCH PER SIM
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

// SMS list
app.get("/sms", (req, res) => {
    res.json(smsList);
});

// 🧪 TEST
app.post("/test", (req, res) => {
    const test = {
        id: Date.now(),
        expected: req.body.expected,
        simId: req.body.simId, // 🔥 QUI
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

// 📶 REGISTRA SIM
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

// 📶 LISTA SIM
app.get("/sims", (req, res) => {
    res.json(sims);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("Server avviato su porta", PORT);
});