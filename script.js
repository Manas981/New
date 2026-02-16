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
const paymentForm = document.getElementById("paymentForm");


async function parseApiResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const raw = await response.text();

  if (!raw) {
    return {};
  }

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(raw);
    } catch (_error) {
      return { error: "Invalid JSON response from server." };
    }
  }

  try {
    return JSON.parse(raw);
  } catch (_error) {
    return {
      error: "Backend API unavailable. Start the Node server for API routes.",
    };
  }
}

const attackData = [
  { type: "Phishing", count: 32, color: "#ed1c3c" },
  { type: "Malware", count: 19, color: "#f97316" },
  { type: "DDoS", count: 11, color: "#3b82f6" },
  { type: "Credential Stuffing", count: 27, color: "#0a2f6a" },
  { type: "Insider Threat", count: 8, color: "#7c3aed" },
];

const fallbackFraudRows = [
  ["TXN-88219", "XXXX3391", "High", "Device mismatch + geo anomaly"],
  ["TXN-88233", "XXXX0177", "Medium", "Rapid transfer burst"],
  ["TXN-88247", "XXXX7290", "High", "Known mule account link"],
  ["TXN-88261", "XXXX1105", "Medium", "Night-time high-value attempt"],
];

let selectedRole = "user";
let otpRequested = false;
let localOtp = "";
let loggedInUserId = "";

const demoCreds = {
  userMpin: "123456",
  admin: { email: "admin@bank.com", mpin: "999999" },
};

let bankingState = {
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
    localOtp = "";
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

    const payload = await parseApiResponse(response);
    if (!response.ok) {
      throw new Error(payload.error || "Unable to send OTP");
    }

    otpBox.classList.remove("hidden");
    otpRequested = true;
    localOtp = "";
    showToast("OTP sent successfully to your email.");
  } catch (error) {
    localOtp = String(Math.floor(100000 + Math.random() * 900000));
    otpRequested = true;
    otpBox.classList.remove("hidden");
    showToast(`OTP service unavailable. Demo OTP: ${localOtp}`);
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

  if (selectedRole === "admin") {
    if (email !== demoCreds.admin.email) {
      showToast("Unknown admin account. Use admin@bank.com.");
      return;
    }

    if (!mpin) {
      showToast("Enter admin MPIN.");
      return;
    }

    if (mpin !== demoCreds.admin.mpin) {
      showToast("Admin MPIN incorrect.");
      return;
    }

    loginToAdmin();
    return;
  }

  const validMpin = mpin && mpin === demoCreds.userMpin;
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

  if (localOtp) {
    if (otp !== localOtp) {
      showToast("Invalid OTP.");
      return;
    }

    localOtp = "";
    loginToUser(email);
    return;
  }

  try {
    const response = await fetch("/api/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, otp }),
    });

    const payload = await parseApiResponse(response);
    if (!response.ok || !payload.verified) {
      throw new Error(payload.error || "OTP verification failed.");
    }

    loginToUser(email);
  } catch (error) {
    showToast(error.message || "Invalid OTP.");
  }
});

paymentForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const type = document.getElementById("paymentType").value;
  const counterparty = document.getElementById("counterparty").value.trim();
  const amount = Number(document.getElementById("paymentAmount").value);
  const note = document.getElementById("paymentNote").value.trim();

  if (!counterparty) {
    showToast("Enter a counterparty account.");
    return;
  }

  if (!amount || amount <= 0) {
    showToast("Enter a valid amount.");
    return;
  }

  if (!loggedInUserId) {
    showToast("Session missing. Please login again.");
    return;
  }

  try {
    const response = await fetch("/api/payment", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user_id: loggedInUserId,
        type,
        counterparty,
        amount,
        note,
      }),
    });

    const payload = await parseApiResponse(response);

    if (!response.ok) {
      if (payload.blocked) {
        showToast("Transaction denied due to suspected fraud.");
        return;
      }
      throw new Error(payload.error || payload.message || "Payment failed.");
    }

    bankingState = payload.ledger || bankingState;
    renderUserBankingData();

    if (payload.blocked) {
      showToast("Transaction denied due to suspected fraud.");
    } else {
      showToast(`${payload.message} Risk: ${payload.scores.fraud_risk_score.toFixed(3)}`);
      paymentForm.reset();
    }
  } catch (error) {
    showToast(error.message || "Payment service unavailable.");
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
  localOtp = "";
  loggedInUserId = "";
});

async function fetchUserLedger(userId) {
  try {
    const response = await fetch(`/api/user-dashboard?user_id=${encodeURIComponent(userId)}`);
    const payload = await parseApiResponse(response);
    if (!response.ok) {
      throw new Error(payload.error || "Unable to fetch dashboard data.");
    }
    bankingState = payload;
  } catch (_error) {
    // Keep default local state when backend is unavailable.
  }
}

function renderUserBankingData() {
  const accountList = document.getElementById("accountList");
  const txnList = document.getElementById("txnList");
  const requestList = document.getElementById("requestList");

  accountList.innerHTML = `
    <li><span>Savings A/C</span><strong>₹ ${bankingState.balances.savings.toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</strong></li>
    <li><span>Current A/C</span><strong>₹ ${bankingState.balances.current.toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</strong></li>
    <li><span>Credit Card Due</span><strong>₹ ${bankingState.balances.creditDue.toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</strong></li>
  `;

  txnList.innerHTML = "";
  bankingState.transactions.slice(0, 8).forEach((txn) => {
    const li = document.createElement("li");

    let amountHtml = `<strong>—</strong>`;
    if (txn.amount < 0) {
      amountHtml = `<strong class="amount-out">- ₹ ${Math.abs(txn.amount).toLocaleString("en-IN")}</strong>`;
    } else if (txn.amount > 0) {
      amountHtml = `<strong class="amount-in">+ ₹ ${txn.amount.toLocaleString("en-IN")}</strong>`;
    }

    li.innerHTML = `<span>${txn.title}</span>${amountHtml}`;
    txnList.appendChild(li);
  });

  requestList.innerHTML = "";
  if (!bankingState.requests.length) {
    requestList.innerHTML = `<li><span>No pending fund requests.</span><strong>—</strong></li>`;
    return;
  }

  bankingState.requests.slice(0, 8).forEach((item) => {
    const li = document.createElement("li");
    li.innerHTML = `<span>${item.from} · ${item.note}</span><strong class="amount-in">₹ ${item.amount.toLocaleString("en-IN")}</strong>`;
    requestList.appendChild(li);
  });
}

async function renderAdminFraudQueue() {
  const body = document.getElementById("fraudBody");
  body.innerHTML = "";

  try {
    const response = await fetch("/api/admin/fraud-transactions");
    const payload = await parseApiResponse(response);

    if (!response.ok) {
      throw new Error(payload.error || "Unable to fetch fraud alerts.");
    }

    if (!payload.items.length) {
      body.innerHTML = `<tr><td colspan="4">No blocked fraudulent transactions yet.</td></tr>`;
      return;
    }

    payload.items.forEach((item) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${item.transaction_id}</td>
        <td>${item.user_id}</td>
        <td class="risk-high">${item.risk}</td>
        <td>${item.reason} (${item.type} ₹${Number(item.amount).toLocaleString("en-IN")})</td>
      `;
      body.appendChild(tr);
    });
  } catch (_error) {
    fallbackFraudRows.forEach(([txn, account, risk, reason]) => {
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
}

async function loginToUser(email) {
  loggedInUserId = email;
  loginView.classList.remove("active");
  logoutBtn.hidden = false;
  userView.classList.add("active");
  adminView.classList.remove("active");
  document.getElementById("userName").textContent = email.split("@")[0];
  await fetchUserLedger(email);
  renderUserBankingData();
  showToast("User login successful.");
}

async function loginToAdmin() {
  loginView.classList.remove("active");
  logoutBtn.hidden = false;
  adminView.classList.add("active");
  userView.classList.remove("active");
  await renderAdminFraudQueue();
  drawAttackChart();
  showToast("Admin login successful.");
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
