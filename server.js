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
//                    OTP SECTION
// =====================================================
const otpStore = new Map(); // phone -> { hash, expiresAt, attempts, lastSent }
const verifiedPhones = new Map(); // phone -> expiresAt

const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 min
const RESEND_COOLDOWN_MS = 30 * 1000; // 30 sec
const MAX_ATTEMPTS = 5;

const hashOtp = (phone, otp) =>
  crypto
    .createHmac("sha256", process.env.OTP_SECRET || "change-this-secret")
    .update(phone + otp)
    .digest("hex");

const isValidPhone = (p) => /^[6-9]\d{9}$/.test(p); // Indian 10-digit number

// >>>>>> YAHAN APNA OTP/SMS API DALNA <<<<<<
// Abhi Fast2SMS ka example hai. Dusra provider (MSG91, Twilio etc.) use
// karna ho to sirf is function ko edit karo.
async function sendOtpSms(phone, otp) {
  if (!process.env.SMS_API_KEY) {
    // API key nahi hai to testing mode: OTP console/logs me dikhega
    console.log(`[DEV MODE] OTP for ${phone}: ${otp}`);
    return;
  }

  const response = await fetch("https://www.fast2sms.com/dev/bulkV2", {
    method: "POST",
    headers: {
      authorization: process.env.SMS_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      route: "otp",
      variables_values: otp,
      numbers: phone,
    }),
  });

  const data = await response.json();
  if (!data.return) {
    throw new Error(data.message || "SMS provider error");
  }
}

// POST /api/send-otp   body: { phone }
app.post("/api/send-otp", async (req, res) => {
  try {
    const phone = String(req.body.phone || "").trim();
    if (!isValidPhone(phone)) {
      return res.status(400).json({ success: false, message: "Invalid phone number" });
    }

    const existing = otpStore.get(phone);
    if (existing && Date.now() - existing.lastSent < RESEND_COOLDOWN_MS) {
      return res
        .status(429)
        .json({ success: false, message: "Please wait before requesting another OTP" });
    }

    const otp = String(crypto.randomInt(100000, 1000000));
    await sendOtpSms(phone, otp);

    otpStore.set(phone, {
      hash: hashOtp(phone, otp),
      expiresAt: Date.now() + OTP_EXPIRY_MS,
      attempts: 0,
      lastSent: Date.now(),
    });

    res.json({ success: true, message: "OTP sent" });
  } catch (err) {
    console.error("send-otp error:", err.message);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// POST /api/verify-otp   body: { phone, otp }
app.post("/api/verify-otp", (req, res) => {
  const phone = String(req.body.phone || "").trim();
  const otp = String(req.body.otp || "").trim();

  const record = otpStore.get(phone);
  if (!record) {
    return res.status(400).json({ success: false, message: "OTP not found, request a new one" });
  }
  if (Date.now() > record.expiresAt) {
    otpStore.delete(phone);
    return res.status(400).json({ success: false, message: "OTP expired" });
  }
  if (record.attempts >= MAX_ATTEMPTS) {
    otpStore.delete(phone);
    return res.status(429).json({ success: false, message: "Too many attempts, request a new OTP" });
  }

  record.attempts += 1;

  const a = Buffer.from(record.hash);
  const b = Buffer.from(hashOtp(phone, otp));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(400).json({ success: false, message: "Incorrect OTP" });
  }

  otpStore.delete(phone);
  verifiedPhones.set(phone, Date.now() + 10 * 60 * 1000); // 10 min verified
  res.json({ success: true, message: "OTP verified" });
});

// =====================================================
//                 PAYMENT SECTION (Razorpay)
// =====================================================
// >>>>>> YAHAN APNA PAYMENT GATEWAY KEY DALNA (.env me) <<<<<<
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

// POST /api/create-order   body: { amount (in rupees), phone? }
app.post("/api/create-order", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(500).json({ success: false, message: "Payment gateway not configured" });
    }

    const amount = Number(req.body.amount);
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    // Optional: payment se pehle OTP verified hona zaroori
    if (process.env.REQUIRE_OTP_BEFORE_PAYMENT === "true") {
      const phone = String(req.body.phone || "").trim();
      const exp = verifiedPhones.get(phone);
      if (!exp || Date.now() > exp) {
        return res.status(401).json({ success: false, message: "Phone not verified" });
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
