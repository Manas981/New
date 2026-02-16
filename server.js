const crypto = require("crypto");
const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();
const port = process.env.PORT || 5000;
const EPSILON = 1e-9;
const EARTH_RADIUS_KM = 6371;
const FRAUD_BLOCK_THRESHOLD = 0.7;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

const otpStore = new Map();
const userFraudState = new Map();
const blockedFraudTransactions = [];

const userLedger = new Map();

const smtpUser = process.env.SMTP_USER || "neobank399@gmail.com";
const smtpPass = process.env.SMTP_PASS;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: smtpUser,
    pass: smtpPass,
  },
});

const fallbackGeo = {
  "8.8.8.8": { lat: 37.386, lon: -122.0838, asn: "AS15169" },
  "1.1.1.1": { lat: -33.8688, lon: 151.2093, asn: "AS13335" },
  "127.0.0.1": { lat: 28.6139, lon: 77.209, asn: "ASLOCAL" },
  "::1": { lat: 28.6139, lon: 77.209, asn: "ASLOCAL" },
};

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const rLat1 = (lat1 * Math.PI) / 180;
  const rLat2 = (lat2 * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(rLat1) * Math.cos(rLat2) * Math.sin(dLon / 2) ** 2;

  return 2 * EARTH_RADIUS_KM * Math.asin(Math.sqrt(a));
}

function mean(values) {
  if (!values.length) {
    return 0;
  }
  return values.reduce((acc, n) => acc + n, 0) / values.length;
}

function std(values) {
  if (values.length < 2) {
    return 0;
  }
  const m = mean(values);
  const variance = values.reduce((acc, v) => acc + (v - m) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function getGeo(ipAddress) {
  return fallbackGeo[ipAddress] || { lat: 0, lon: 0, asn: "ASN_UNKNOWN" };
}

function getFraudState(userId) {
  if (!userFraudState.has(userId)) {
    userFraudState.set(userId, {
      amounts: [],
      timestamps: [],
      geoDistances: [],
      lastLat: null,
      lastLon: null,
      lastAsn: null,
      lastTimestamp: null,
    });
  }
  return userFraudState.get(userId);
}

function computeFraudScores(transaction) {
  const { user_id: userId, timestamp, amount, ip_address: ipAddress } = transaction;
  const state = getFraudState(userId);
  const txTime = new Date(timestamp);

  const muU = state.amounts.length ? mean(state.amounts) : amount;
  const sigmaU = state.amounts.length > 1 ? std(state.amounts) : 0;
  const sSpend = Math.abs(amount - muU) / (sigmaU + EPSILON);
  const sSpendNorm = sigmoid(sSpend);

  const oneHourAgo = new Date(txTime.getTime() - 60 * 60 * 1000);
  const nw = state.timestamps.filter((ts) => ts >= oneHourAgo && ts <= txTime).length + 1;

  const byHour = {};
  state.timestamps.forEach((ts) => {
    const h = new Date(ts);
    h.setMinutes(0, 0, 0);
    const key = h.toISOString();
    byHour[key] = (byHour[key] || 0) + 1;
  });
  const hourlyCounts = Object.values(byHour);
  const lambdaU = hourlyCounts.length ? mean(hourlyCounts) : 0;
  const sigmaLambda = hourlyCounts.length > 1 ? std(hourlyCounts) : 0;
  const sVelocity = (nw - lambdaU) / (sigmaLambda + EPSILON);
  const sVelocityNorm = sigmoid(sVelocity);

  const geo = getGeo(ipAddress);
  let distanceKm = 0;
  let sSpeed = 0;
  let sAsn = 0;
  let sHist = 0;

  if (state.lastLat !== null && state.lastLon !== null && state.lastTimestamp) {
    distanceKm = haversineKm(state.lastLat, state.lastLon, geo.lat, geo.lon);
    const deltaHours = Math.max((txTime - state.lastTimestamp) / (1000 * 3600), EPSILON);
    const v = distanceKm / deltaHours;
    sSpeed = Math.min(1, v / 900);
    sAsn = geo.asn !== state.lastAsn ? 1 : 0;
    const geoStd = state.geoDistances.length > 1 ? std(state.geoDistances) : 0;
    sHist = distanceKm / (geoStd + EPSILON);
  }

  const sGeo = 0.5 * sSpeed + 0.3 * sHist + 0.2 * sAsn;
  const sGeoNorm = sigmoid(sGeo);

  const riskRaw = 0.4 * sSpendNorm + 0.3 * sVelocityNorm + 0.3 * sGeoNorm;
  const riskFinal = sigmoid(riskRaw);

  state.amounts.push(amount);
  state.timestamps.push(txTime);
  if (state.lastLat !== null && state.lastLon !== null) {
    state.geoDistances.push(distanceKm);
  }
  state.lastLat = geo.lat;
  state.lastLon = geo.lon;
  state.lastAsn = geo.asn;
  state.lastTimestamp = txTime;

  return {
    spending_score: sSpendNorm,
    velocity_score: sVelocityNorm,
    geo_score: sGeoNorm,
    fraud_risk_score: riskFinal,
  };
}

function getUserLedger(userId) {
  if (!userLedger.has(userId)) {
    userLedger.set(userId, {
      balances: {
        savings: 245900.5,
        current: 870110.0,
        creditDue: 12480.0,
      },
      transactions: [
        { title: "UPI to GroceryHub", amount: -1240 },
        { title: "Salary Credit", amount: 96000 },
        { title: "EMI Auto Debit", amount: -19840 },
        { title: "Interest Payout", amount: 2330 },
      ],
      requests: [
        { from: "AC45312098", amount: 2200, note: "Team lunch split" },
        { from: "AC99081134", amount: 12500, note: "Vendor pending invoice" },
      ],
    });
  }
  return userLedger.get(userId);
}

app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body || {};

  if (!email || !validEmail(email)) {
    return res.status(400).json({ error: "Valid email is required." });
  }

  if (!smtpPass) {
    return res.status(500).json({
      error:
        "SMTP is not configured. Set SMTP_PASS (Gmail app password) for neobank399@gmail.com.",
    });
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 5 * 60 * 1000;
  otpStore.set(email.toLowerCase(), { otp, expiresAt });

  try {
    await transporter.sendMail({
      from: `NeoBank Security <${smtpUser}>`,
      to: email,
      subject: "Your NeoBank OTP for MPIN reset",
      text: `Your OTP is ${otp}. It is valid for 5 minutes.`,
      html: `<p>Your OTP is <strong>${otp}</strong>.</p><p>This OTP is valid for 5 minutes.</p>`,
    });

    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: "Failed to send OTP email." });
  }
});

app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body || {};
  const key = (email || "").toLowerCase();

  if (!key || !otp) {
    return res.status(400).json({ error: "Email and OTP are required." });
  }

  const record = otpStore.get(key);
  if (!record) {
    return res.status(400).json({ error: "OTP not requested for this email." });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(key);
    return res.status(400).json({ error: "OTP expired. Please request a new OTP." });
  }

  if (String(otp) !== record.otp) {
    return res.status(400).json({ error: "Invalid OTP." });
  }

  otpStore.delete(key);
  return res.json({ verified: true });
});

app.get("/api/user-dashboard", (req, res) => {
  const userId = String(req.query.user_id || "").toLowerCase();
  if (!userId) {
    return res.status(400).json({ error: "user_id is required." });
  }
  return res.json(getUserLedger(userId));
});

app.post("/api/payment", (req, res) => {
  const { user_id: userIdRaw, type, counterparty, amount, note } = req.body || {};
  const userId = String(userIdRaw || "").toLowerCase();
  const amt = Number(amount);

  if (!userId || !counterparty || !type || !amt || amt <= 0) {
    return res.status(400).json({ error: "Invalid payment payload." });
  }

  const tx = {
    transaction_id: `TXN-${Date.now()}`,
    user_id: userId,
    timestamp: new Date().toISOString(),
    amount: amt,
    ip_address: req.ip,
    device_hash: crypto
      .createHash("sha256")
      .update(String(req.headers["user-agent"] || "unknown"))
      .digest("hex")
      .slice(0, 16),
  };

  const scores = computeFraudScores(tx);

  if (scores.fraud_risk_score >= FRAUD_BLOCK_THRESHOLD) {
    const blocked = {
      transaction_id: tx.transaction_id,
      user_id: tx.user_id,
      amount: tx.amount,
      reason: "Blocked by fraud engine",
      risk: Number(scores.fraud_risk_score.toFixed(4)),
      type,
      counterparty,
      timestamp: tx.timestamp,
    };
    blockedFraudTransactions.unshift(blocked);

    return res.status(403).json({
      blocked: true,
      message: "Transaction denied due to suspected fraud.",
      scores,
    });
  }

  const ledger = getUserLedger(userId);

  if (type === "transfer") {
    if (amt > ledger.balances.savings) {
      return res.status(400).json({ error: "Insufficient savings balance for transfer." });
    }

    ledger.balances.savings -= amt;
    ledger.transactions.unshift({
      title: `Transfer to ${counterparty}${note ? ` (${note})` : ""}`,
      amount: -amt,
    });
  } else if (type === "request") {
    ledger.requests.unshift({
      from: counterparty,
      amount: amt,
      note: note || "Fund request",
    });
    ledger.transactions.unshift({
      title: `Request sent to ${counterparty}${note ? ` (${note})` : ""}`,
      amount: 0,
    });
  } else {
    return res.status(400).json({ error: "Unknown payment type." });
  }

  return res.json({
    blocked: false,
    message: "Payment processed successfully.",
    scores,
    ledger,
  });
});

app.get("/api/admin/fraud-transactions", (_req, res) => {
  return res.json({
    count: blockedFraudTransactions.length,
    items: blockedFraudTransactions,
  });
});

app.listen(port, () => {
  console.log(`NeoBank app running at http://localhost:${port}`);
});
