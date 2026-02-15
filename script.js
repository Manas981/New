const loginView = document.getElementById("loginView");
const userView = document.getElementById("userView");
const adminView = document.getElementById("adminView");
const logoutBtn = document.getElementById("logoutBtn");
const loginBtn = document.getElementById("loginBtn");
const forgotBtn = document.getElementById("forgotBtn");
const forgotWrap = document.getElementById("forgotWrap");
const otpBox = document.getElementById("otpBox");
const toast = document.getElementById("toast");
const otpInput = document.getElementById("otp");

const roleButtons = document.querySelectorAll(".role-btn");

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

let selectedRole = "user";
let otpRequested = false;

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
    otpRequested = false;
    otpInput.value = "";
  });
});

forgotBtn.addEventListener("click", async () => {
  const email = document.getElementById("email").value.trim().toLowerCase();
  if (!email) {
    showToast("Please enter your email first.");
    return;
  }

  forgotBtn.disabled = true;
  forgotBtn.textContent = "Sending OTP...";

  try {
    const response = await fetch("/api/send-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Unable to send OTP");
    }

    otpBox.classList.remove("hidden");
    otpRequested = true;
    showToast("OTP sent successfully to your email.");
  } catch (error) {
    showToast(error.message || "OTP send failed.");
  } finally {
    forgotBtn.disabled = false;
    forgotBtn.textContent = "Forgot MPIN? Send OTP";
  }
});

loginBtn.addEventListener("click", async () => {
  const email = document.getElementById("email").value.trim().toLowerCase();
  const mpin = document.getElementById("mpin").value.trim();
  const otp = otpInput.value.trim();

  if (!email) {
    showToast("Enter your email.");
    return;
  }

  const creds = demoCreds[selectedRole];

  if (email !== creds.email) {
    showToast("Unknown account. Use demo credentials.");
    return;
  }

  if (selectedRole === "admin") {
    if (!mpin) {
      showToast("Enter admin MPIN.");
      return;
    }

    if (mpin !== creds.mpin) {
      showToast("Admin MPIN incorrect.");
      return;
    }

    loginToAdmin();
    return;
  }

  // User flow: login by MPIN OR OTP (MPIN not mandatory for OTP login)
  const validMpin = mpin && mpin === creds.mpin;
  if (validMpin) {
    loginToUser(email);
    return;
  }

  if (!otpRequested) {
    showToast("Enter valid MPIN or use Forgot MPIN to receive OTP.");
    return;
  }

  if (!otp) {
    showToast("Enter OTP to login.");
    return;
  }

  try {
    const response = await fetch("/api/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, otp }),
    });

    const payload = await response.json();
    if (!response.ok || !payload.verified) {
      throw new Error(payload.error || "OTP verification failed.");
    }

    loginToUser(email);
  } catch (error) {
    showToast(error.message || "Invalid OTP.");
  }
});

logoutBtn.addEventListener("click", () => {
  [userView, adminView].forEach((v) => v.classList.remove("active"));
  loginView.classList.add("active");
  logoutBtn.hidden = true;

  document.getElementById("email").value = "";
  document.getElementById("mpin").value = "";
  otpInput.value = "";
  otpBox.classList.add("hidden");
  otpRequested = false;
});

function loginToUser(email) {
  loginView.classList.remove("active");
  logoutBtn.hidden = false;
  userView.classList.add("active");
  adminView.classList.remove("active");
  document.getElementById("userName").textContent = email.split("@")[0];
  showToast("User login successful.");
}

function loginToAdmin() {
  loginView.classList.remove("active");
  logoutBtn.hidden = false;
  adminView.classList.add("active");
  userView.classList.remove("active");
  renderFraudTable();
  drawAttackChart();
  showToast("Admin login successful.");
}

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
