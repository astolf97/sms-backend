const path = require("path");
app.use(express.static(path.join(__dirname)));

const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

let smsList = [];

app.get("/", (req, res) => {
    res.send("Backend SMS attivo");
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