// Replace the whole script.js with this
const loginView = document.getElementById("loginView");
const userView = document.getElementById("userView");
const adminView = document.getElementById("adminView");
const logoutBtn = document.getElementById("logoutBtn");
const loginBtn = document.getElementById("loginBtn");
const forgotBtn = document.getElementById("forgotBtn");
const forgotWrap = document.getElementById("forgotWrap");
const otpBox = document.getElementById("otpBox");
const toast = document.getElementById("toast");

const roleButtons = document.querySelectorAll(".role-btn");

let selectedRole = "user";
let otpVerified = false;
let otpRequestedFor = null;

const demoCreds = {
  user: { email: "user@bank.com", mpin: "123456" },
  admin: { email: "admin@bank.com", mpin: "999999" },
};

roleButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    roleButtons.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    selectedRole = btn.dataset.role;
    const isUser = selectedRole === "user";
    forgotWrap.style.display = isUser ? "block" : "none";
    otpBox.classList.add("hidden");
    otpVerified = false;
    otpRequestedFor = null;
  });
});

/* --- NEW: call server to send OTP --- */
forgotBtn.addEventListener("click", async () => {
  const email = document.getElementById("email").value.trim();
  if (!email) {
    showToast("Please enter your email first.");
    return;
  }

  try {
    showToast("Requesting OTP…");
    const resp = await fetch("/api/send-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });

    const data = await resp.json();
    if (!resp.ok) {
      // server returned an error message (useful for debugging)
      showToast(data.error || "Failed to request OTP.");
      console.error("OTP request failed:", data);
      return;
    }

    // success
    otpBox.classList.remove("hidden");
    otpRequestedFor = email.toLowerCase();
    otpVerified = false;
    showToast(`OTP sent to ${email}. Check your inbox (and spam).`);
  } catch (err) {
    console.error("Network or server error requesting OTP:", err);
    showToast("Network error: could not reach server.");
  }
});

loginBtn.addEventListener("click", async () => {
  const email = document.getElementById("email").value.trim().toLowerCase();
  const mpin = document.getElementById("mpin").value.trim();
  const otp = document.getElementById("otp").value.trim();

  if (!email || !mpin) {
    showToast("Enter both email and MPIN.");
    return;
  }

  const creds = demoCreds[selectedRole];

  if (email !== creds.email) {
    showToast("Unknown account. Use demo credentials.");
    return;
  }

  const validMpin = mpin === creds.mpin;

  if (!validMpin && selectedRole === "user") {
    if (!otpRequestedFor || otpRequestedFor !== email) {
      showToast("MPIN incorrect. Use Forgot MPIN to request OTP for this email.");
      return;
    }

    try {
      const resp = await fetch("/api/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        showToast(data.error || "OTP verification failed.");
        return;
      }
      if (data.verified) otpVerified = true;
    } catch (err) {
      console.error("OTP verify error:", err);
      showToast("Network error verifying OTP.");
      return;
    }
  }

  if (!validMpin && selectedRole === "admin") {
    showToast("Admin MPIN incorrect.");
    return;
  }

  if (selectedRole === "user" && !validMpin && !otpVerified) {
    showToast("OTP verification required.");
    return;
  }

  loginView.classList.remove("active");
  logoutBtn.hidden = false;

  if (selectedRole === "user") {
    userView.classList.add("active");
    document.getElementById("userName").textContent = email.split("@")[0];
    showToast("User login successful.");
  } else {
    adminView.classList.add("active");
    renderFraudTable();
    drawAttackChart();
    showToast("Admin login successful.");
  }
});

logoutBtn.addEventListener("click", () => {
  [userView, adminView].forEach((v) => v.classList.remove("active"));
  loginView.classList.add("active");
  logoutBtn.hidden = true;

  document.getElementById("email").value = "";
  document.getElementById("mpin").value = "";
  document.getElementById("otp").value = "";
  otpBox.classList.add("hidden");
  otpRequestedFor = null;
  otpVerified = false;
});

/* --- keep the rest of the UI helpers the same --- */
const attackData = [
  { type: "Phishing", count: 32, color: "#ed1c3c" },
  { type: "Malware", count: 19, color: "#f97316" },
  { type: "DDoS", count: 11, color: "#3b82f6" },
  { type: "Credential Stuffing", count: 27, color: "#0a2f6a" },
  { type: "Insider Threat", count: 8, color: "#7c3aed" },
];

const fraudRows = [
  ["TXN-88219", "XXXX3391", "High", "Device mismatch + geo anomaly"],
  ["TXN-88233", "XXXX0177", "Medium", "Rapid transfer burst"],
  ["TXN-88247", "XXXX7290", "High", "Known mule account link"],
  ["TXN-88261", "XXXX1105", "Medium", "Night-time high-value attempt"],
];

function renderFraudTable() {
  const body = document.getElementById("fraudBody");
  body.innerHTML = "";
  fraudRows.forEach(([txn, account, risk, reason]) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${txn}</td>
      <td>${account}</td>
      <td class="${risk === "High" ? "risk-high" : "risk-medium"}">${risk}</td>
      <td>${reason}</td>
    `;
    body.appendChild(tr);
  });
}

function drawAttackChart() {
  const canvas = document.getElementById("attackChart");
  const ctx = canvas.getContext("2d");
  const { width, height } = canvas;

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, width, height);

  const max = Math.max(...attackData.map((d) => d.count));
  const left = 45;
  const bottom = height - 35;
  const usableHeight = height - 70;
  const barW = 70;
  const gap = 28;

  ctx.strokeStyle = "#cbd5e1";
  ctx.beginPath();
  ctx.moveTo(left, 20);
  ctx.lineTo(left, bottom);
  ctx.lineTo(width - 10, bottom);
  ctx.stroke();

  attackData.forEach((item, i) => {
    const x = left + 20 + i * (barW + gap);
    const barH = (item.count / max) * usableHeight;
    const y = bottom - barH;

    ctx.fillStyle = item.color;
    ctx.fillRect(x, y, barW, barH);

    ctx.fillStyle = "#1f2937";
    ctx.font = "12px Inter";
    ctx.fillText(String(item.count), x + 24, y - 8);

    const words = item.type.split(" ");
    words.forEach((word, idx) => {
      ctx.fillText(word, x, bottom + 14 + idx * 12);
    });
  });
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2200);
}
