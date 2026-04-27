const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());

// ✅ serve index.html
app.use(express.static(path.join(__dirname)));

let smsList = [];

// 👉 opzionale: apre dashboard direttamente su /
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/sms", (req, res) => {
    const sms = req.body;
    smsList.push(sms);
    console.log("SMS ricevuto:", sms);
    res.send({ status: "ok" });
});

app.get("/sms", (req, res) => {
    res.json(smsList);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("Server avviato su porta", PORT);
});