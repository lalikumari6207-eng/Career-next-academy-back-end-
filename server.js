require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Razorpay = require("razorpay");
 
const app = express();
app.use(express.json());

// ---------- CORS ----------
// FRONTEND_URL me apne frontend ka link daalna (comma se multiple allowed)
const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(",").map((s) => s.trim())
  : null;

app.use(
  cors({
    origin: allowedOrigins || true,
  })
);

// ---------- HEALTH CHECK ----------
app.get("/", (req, res) => res.send("Backend is running ✅"));

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
      subject: "Your OTP Code",
      htmlContent: `
        <div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:20px;border:1px solid #eee;border-radius:8px">
          <h2 style="margin:0 0 12px">Your OTP Code</h2>
          <p style="font-size:32px;letter-spacing:6px;font-weight:bold;margin:12px 0">${otp}</p>
          <p style="color:#555;margin:0">Valid for 5 minutes. Do not share this code with anyone.</p>
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

// POST /api/create-order   body: { amount (in rupees), email? }
app.post("/api/create-order", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(500).json({ success: false, message: "Payment gateway not configured" });
    }

    const amount = Number(req.body.amount);
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    // Optional: payment se pehle email OTP verified hona zaroori
    if (process.env.REQUIRE_OTP_BEFORE_PAYMENT === "true") {
      const email = String(req.body.email || "").trim().toLowerCase();
      const exp = verifiedEmails.get(email);
      if (!exp || Date.now() > exp) {
        return res.status(401).json({ success: false, message: "Email not verified" });
      }
    }

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100), // paise me
      currency: "INR",
      receipt: "rcpt_" + Date.now(),
    });

    res.json({
      success: true,
      order,
      key_id: process.env.RAZORPAY_KEY_ID, // frontend ko sirf key_id dena, secret kabhi nahi
    });
  } catch (err) {
    console.error("create-order error:", err);
    res.status(500).json({ success: false, message: "Could not create order" });
  }
});

// POST /api/verify-payment
// body: { razorpay_order_id, razorpay_payment_id, razorpay_signature }
app.post("/api/verify-payment", (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ success: false, message: "Missing payment details" });
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || "")
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");

    const a = Buffer.from(expected);
    const b = Buffer.from(razorpay_signature);
    const valid = a.length === b.length && crypto.timingSafeEqual(a, b);

    if (!valid) {
      return res.status(400).json({ success: false, message: "Payment verification failed" });
    }

    // TODO: yahan database me order "paid" mark karna / email bhejna etc.
    res.json({ success: true, message: "Payment verified", payment_id: razorpay_payment_id });
  } catch (err) {
    console.error("verify-payment error:", err.message);
    res.status(500).json({ success: false, message: "Verification error" });
  }
});

// ---------- START ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
