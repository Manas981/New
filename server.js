// Replace your server.js with this improved version
require("dotenv").config();

const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

const otpStore = new Map();

const smtpUser = process.env.SMTP_USER || "neobank399@gmail.com";
const smtpPass = process.env.SMTP_PASS || "";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: smtpUser,
    pass: smtpPass,
  },
});

// verify transporter at startup so SMTP issues appear in console immediately
transporter.verify((err, success) => {
  if (err) {
    console.error("SMTP transporter verify failed. Check SMTP credentials and network.", err);
  } else {
    console.log("SMTP transporter ready:", success);
  }
});

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body || {};

  if (!email || !validEmail(email)) {
    return res.status(400).json({ error: "Valid email is required." });
  }

  if (!smtpPass) {
    return res.status(500).json({
      error:
        "SMTP is not configured. Set SMTP_PASS (Gmail app password) in your .env file.",
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
    console.error("Failed to send OTP email:", error);
    // include server-side error message to help debug (safe in dev; remove in prod)
    return res.status(500).json({ error: "Failed to send OTP email.", details: error.message });
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

app.listen(port, () => {
  console.log(`NeoBank app running at http://localhost:${port}`);
});
