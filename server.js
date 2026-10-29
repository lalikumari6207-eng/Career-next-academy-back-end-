require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const { createRemoteJWKSet, jwtVerify } = require("jose");
const { PROGRAMS, REG_FEE } = require("./programs");

const app = express();
app.set("trust proxy", 1);

// ---------- Razorpay Webhook (raw body chahiye, isliye express.json se PEHLE) ----------
app.post("/api/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET || "";
    const expected = crypto.createHmac("sha256", secret).update(req.body).digest("hex");
    const got = String(req.headers["x-razorpay-signature"] || "");
    if (!secret || expected.length !== got.length ||
        !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(got))) {
      return res.status(400).send("Invalid signature");
    }
    const event = JSON.parse(req.body.toString());
    if (event.event === "payment.captured") {
      const p = event.payload.payment.entity;
      const order = await razorpay.orders.fetch(p.order_id);
      recordPayment(order, p.id);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("webhook error:", e.message);
    res.status(500).send("error");
  }
});

app.use(express.json());

// ---------- CORS ----------
// FRONTEND_URL (purana) aur ALLOWED_ORIGINS (naya) dono padhe jaate hain, comma se multiple allowed
const allowedOrigins = [process.env.FRONTEND_URL, process.env.ALLOWED_ORIGINS]
  .filter(Boolean).join(",").split(",").map((x) => x.trim().replace(/\/$/, "")).filter(Boolean);

app.use(
  cors({
    origin: allowedOrigins.length ? allowedOrigins : true,
  })
);

// ---------- HEALTH CHECK ----------
app.get("/", (req, res) => res.send("Backend is running ✅"));
// ===== Lead tracking routes =====
const fs = require('fs');
const FILE = './leads.json';
const ADMIN_PASS = process.env.ADMIN_PASS || 'careernext@2026';
const read = () => { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { return {}; } };
const write = (d) => fs.writeFileSync(FILE, JSON.stringify(d));
const isAdmin = (req, res, next) =>
  req.headers['x-admin-pass'] === ADMIN_PASS ? next() : res.status(401).json({ success: false, message: 'Unauthorized' });

// registration form yahan stage bhejta hai (public)
app.post('/api/track', (req, res) => {
  const b = req.body || {};
  const email = String(b.email || '').trim().toLowerCase();
  if (!email) return res.json({ success: false });
  const db = read(), now = new Date().toISOString();
  const old = db[email] || { id: email, started_at: now };
  const stage = Math.max(old.stage || 1, +b.stage || 1);
  db[email] = { ...old, ...b, id: email, email, stage, updated_at: now,
    reg_at: stage >= 3 ? (old.reg_at || now) : old.reg_at };
  write(db); res.json({ success: true });
});

app.get('/api/leads', isAdmin, (req, res) => res.json({ success: true, leads: Object.values(read()) }));

app.post('/api/leads/update', isAdmin, (req, res) => {
  const db = read(), { id, ...patch } = req.body || {};
  if (db[id]) { Object.assign(db[id], patch); write(db); }
  res.json({ success: true });
});

app.post('/api/leads/delete', isAdmin, (req, res) => {
  const db = read(); delete db[(req.body || {}).id]; write(db); res.json({ success: true });
});

// =====================================================
//                 EMAIL OTP SECTION
// =====================================================
const otpStore = new Map(); // email -> { hash, expiresAt, attempts, lastSent }
const verifiedEmails = new Map(); // email -> expiresAt

const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 min
const RESEND_COOLDOWN_MS = 30 * 1000; // 30 sec
const MAX_ATTEMPTS = 5;

const hashOtp = (email, otp) =>
  crypto
    .createHmac("sha256", process.env.OTP_SECRET || "change-this-secret")
    .update(email + otp)
    .digest("hex");

const isValidEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);


// >>>>>> EMAIL SETTINGS (Brevo) <<<<<<
async function sendOtpEmail(email, otp) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL || process.env.BREVO_SENDER;
  const logoUrl = process.env.LOGO_URL || "";

  if (!apiKey || !senderEmail) {
    console.log(`[DEV MODE] OTP for ${email}: ${otp}`);
    return;
  }

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      sender: {
        name: process.env.BREVO_SENDER_NAME || "Career Next Academy",
        email: senderEmail,
      },
      to: [{ email }],
      subject: "CareerNext Academy: your verification code",
      textContent: `Your CareerNext Academy verification code is ${otp}. It is valid for 5 minutes. Do not share it with anyone.`,
      htmlContent: `
        <div style="background:#f4f5f7;padding:24px 12px;font-family:Arial,Helvetica,sans-serif">
          <div style="max-width:420px;margin:auto;background:#ffffff;border-radius:10px;padding:28px;text-align:center">
            ${logoUrl ? `<img src="${logoUrl}" alt="CareerNext Academy" width="64" height="64" style="display:block;margin:0 auto 12px;border-radius:12px">` : ""}
            <h2 style="margin:0 0 6px;color:#111">CareerNext Academy</h2>
            <p style="margin:0 0 18px;color:#555;font-size:14px">Your verification code is</p>
            <p style="font-size:34px;letter-spacing:8px;font-weight:bold;margin:0 0 18px;color:#e0184f">${otp}</p>
            <p style="margin:0;color:#777;font-size:12px">Valid for 5 minutes. Do not share this code with anyone.</p>
          </div>
        </div>`,
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Brevo error ${response.status}: ${text}`);
  }
}
// POST /api/send-otp   body: { email }
app.post("/api/send-otp", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: "Invalid email" });
    }

    const existing = otpStore.get(email);
    if (existing && Date.now() - existing.lastSent < RESEND_COOLDOWN_MS) {
      return res
        .status(429)
        .json({ success: false, message: "Please wait before requesting another OTP" });
    }

    const otp = String(crypto.randomInt(100000, 1000000));
    await sendOtpEmail(email, otp);

    otpStore.set(email, {
      hash: hashOtp(email, otp),
      expiresAt: Date.now() + OTP_EXPIRY_MS,
      attempts: 0,
      lastSent: Date.now(),
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (err) {
    console.error("send-otp error:", err.message);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// POST /api/verify-otp   body: { email, otp }
app.post("/api/verify-otp", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const otp = String(req.body.otp || "").trim();

  const record = otpStore.get(email);
  if (!record) {
    return res.status(400).json({ success: false, message: "OTP not found, request a new one" });
  }
  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ success: false, message: "OTP expired" });
  }
  if (record.attempts >= MAX_ATTEMPTS) {
    otpStore.delete(email);
    return res.status(429).json({ success: false, message: "Too many attempts, request a new OTP" });
  }

  record.attempts += 1;

  const a = Buffer.from(record.hash);
  const b = Buffer.from(hashOtp(email, otp));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(400).json({ success: false, message: "Incorrect OTP" });
  }

  otpStore.delete(email);
  verifiedEmails.set(email, Date.now() + 10 * 60 * 1000); // 10 min verified
  res.json({ success: true, message: "OTP verified" });
});

// =====================================================
//                 PAYMENT SECTION (Razorpay)
// =====================================================
// >>>>>> YAHAN APNA PAYMENT GATEWAY KEY DALNA (.env / Render Environment me) <<<<<<
// RAZORPAY_KEY_ID  aur  RAZORPAY_KEY_SECRET
let razorpay = null;
if (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
} else {
  console.warn("⚠️  Razorpay keys missing. Payment routes won't work until you add them.");
}

// ---------- Helpers ----------
// Firebase phone-OTP token check (bina firebase-admin ke, sirf public keys se)
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "";
const JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
);
async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, error: "Mobile OTP verification required" });
    if (!FIREBASE_PROJECT_ID) return res.status(500).json({ success: false, error: "Server not configured (FIREBASE_PROJECT_ID missing)" });
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: "https://securetoken.google.com/" + FIREBASE_PROJECT_ID,
      audience: FIREBASE_PROJECT_ID,
    });
    if (!payload.phone_number) return res.status(401).json({ success: false, error: "Mobile not verified" });
    req.user = { uid: payload.sub, phone: payload.phone_number };
    next();
  } catch (e) {
    res.status(401).json({ success: false, error: "OTP session expired. Please verify again." });
  }
}

// Registration Number: mobile number se bana hota hai (DB ki zarurat nahi)
const regDigits = (phone) =>
  String(10000000 + (parseInt(
    crypto.createHmac("sha256", process.env.OTP_SECRET || "change-this-secret").update("reg|" + phone).digest("hex").slice(0, 12), 16
  ) % 90000000));
const regNoFor = (phone) => "CNA-" + new Date().getFullYear() + "-" + regDigits(phone);
const regNoMatches = (regNo, phone) => {
  const m = /^CNA-\d{4}-(\d{8})$/.exec(String(regNo || "").trim().toUpperCase());
  return !!m && m[1] === regDigits(phone);
};

// Payment records (admin ke dekhne ke liye). NOTE: Render free me file redeploy par mit sakti hai,
// asli record hamesha Razorpay dashboard me rehta hai.
const PAY_FILE = "./payments.json";
const readPays = () => { try { return JSON.parse(fs.readFileSync(PAY_FILE, "utf8")); } catch (e) { return []; } };
function recordPayment(order, paymentId) {
  const n = order.notes || {};
  const list = readPays();
  if (list.some((p) => p.paymentId === paymentId)) return;
  list.push({
    paymentId, orderId: order.id, type: n.type, phone: n.phone, programId: n.programId || null,
    mode: n.mode || null, regNo: n.type === "registration" ? regNoFor(n.phone) : n.regNo || null,
    amount: order.amount / 100, details: n.details || null, paidAt: new Date().toISOString(),
  });
  fs.writeFileSync(PAY_FILE, JSON.stringify(list));
}
app.get("/api/payments", isAdmin, (req, res) => res.json({ success: true, payments: readPays() }));

// POST /api/create-order   (amount backend khud tay karta hai, frontend se nahi)
app.post("/api/create-order", auth, async (req, res) => {
  try {
    if (!razorpay) return res.status(500).json({ success: false, error: "Payment gateway not configured" });
    const { type, programId, mode, regNo, details } = req.body || {};
    let amount;
    const notes = { type: String(type), uid: req.user.uid, phone: req.user.phone };

    if (type === "registration") {
      const done = readPays().find((p) => p.type === "registration" && p.phone === req.user.phone);
      if (done) return res.json({ success: true, alreadyRegistered: true, regNo: done.regNo });
      amount = REG_FEE;
      const d = JSON.stringify(details || {}).slice(0, 200);
      notes.details = d;
    } else if (type === "program") {
      const p = PROGRAMS[programId];
      if (!p) return res.status(400).json({ success: false, error: "Invalid program" });
      if (mode !== "full" && mode !== "installment") return res.status(400).json({ success: false, error: "Invalid payment mode" });
      if (!regNoMatches(regNo, req.user.phone)) {
        return res.status(403).json({ success: false, error: "Registration number does not match this mobile number" });
      }
      amount = mode === "full" ? p.fee - REG_FEE : Math.round(p.fee / p.inst / 100) * 100;
      Object.assign(notes, { programId, mode, regNo: String(regNo).trim().toUpperCase() });
    } else {
      return res.status(400).json({ success: false, error: "Invalid type" });
    }

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100),
      currency: "INR",
      receipt: "rcpt_" + Date.now(),
      notes,
    });
    res.json({ success: true, orderId: order.id, amount: order.amount, currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    console.error("create-order error:", err);
    res.status(500).json({ success: false, error: "Could not create order" });
  }
});

// POST /api/verify-payment
app.post("/api/verify-payment", auth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ success: false, error: "Missing payment details" });
    }
    const expected = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || "")
      .update(razorpay_order_id + "|" + razorpay_payment_id).digest("hex");
    const a = Buffer.from(expected), b = Buffer.from(String(razorpay_signature));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(400).json({ success: false, error: "Payment verification failed" });
    }
    const order = await razorpay.orders.fetch(razorpay_order_id);
    if (!order.notes || order.notes.uid !== req.user.uid) {
      return res.status(403).json({ success: false, error: "Order does not belong to you" });
    }
    recordPayment(order, razorpay_payment_id);
    const n = order.notes;
    res.json({ success: true, type: n.type,
      regNo: n.type === "registration" ? regNoFor(n.phone) : n.regNo,
      programId: n.programId || null, mode: n.mode || null });
  } catch (err) {
    console.error("verify-payment error:", err.message);
    res.status(500).json({ success: false, error: "Verification error" });
  }
});

// ---------- START ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
