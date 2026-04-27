const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ROOT → dashboard
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

let smsList = [];
let tests = [];

// 📩 Ricezione SMS
app.post("/sms", (req, res) => {
    const sms = req.body;
    smsList.push(sms);

    console.log("SMS ricevuto:", sms);

    // 🔥 CHECK TEST
    tests.forEach(test => {
        if (test.status === "PENDING") {
            if (sms.message.toLowerCase().includes(test.expected.toLowerCase())) {
                test.status = "PASS";
                test.result = sms.message;
                test.completedAt = Date.now();
            }
        }
    });

    res.json({ status: "ok" });
});

// 📥 Lista SMS
app.get("/sms", (req, res) => {
    res.json(smsList);
});

// 🧪 Crea test
app.post("/test", (req, res) => {
    const test = {
        id: Date.now(),
        expected: req.body.expected,
        status: "PENDING",
        result: null,
        createdAt: Date.now(),
        completedAt: null,
        timeout: 30000 // 30 sec
    };

    tests.push(test);
    res.json(test);
});

// 📊 Lista test
app.get("/tests", (req, res) => {
    res.json(tests);
});

// ⏱ FAIL automatico
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
}, 2000);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("Server avviato su porta", PORT);
});