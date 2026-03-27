const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const nodemailer = require("nodemailer");
const sgTransport = require("nodemailer-sendgrid-transport");

const User = require("./models/User");

const app = express();
app.use(cors());
app.use(express.json());

// ------------------ CONFIG ------------------

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB error:", err));

// File uploads
const upload = multer({ dest: "uploads/" });

// Email transporter


const transporter = nodemailer.createTransport(
  sgTransport({
    auth: {
      api_key: process.env.SENDGRID_API_KEY
    }
  })
});

// ------------------ AUTH ROUTES ------------------

// ✅ SIGNUP (send verification code)
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ error: "User already exists" });

    const passwordHash = await bcrypt.hash(password, 10);

    const code = Math.floor(100000 + Math.random() * 900000).toString();

    const user = await User.create({
      email,
      passwordHash,
      verificationCode: code,
      verificationCodeExpires: new Date(Date.now() + 10 * 60 * 1000)
    });

    console.log("User created:", email);
    console.log("Verification code:", code);

    // ✅ SEND EMAIL
    try {
    await transporter.sendMail({
  from: "m.elmzouri@enim.ac.ma", // must match SendGrid verified sender
  to: email,
  subject: "Your verification code",
  text: `Your verification code is: ${code}`
});

      console.log("Email sent to:", email);
    } catch (mailErr) {
      console.error("EMAIL ERROR:", mailErr);
      return res.status(500).json({ error: "Failed to send email" });
    }

    res.json({ message: "Verification code sent" });

  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// ✅ VERIFY EMAIL
app.post("/verify", async (req, res) => {
  try {
    const { email, code } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ error: "User not found" });

    if (
      user.verificationCode !== code ||
      user.verificationCodeExpires < new Date()
    ) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    user.isVerified = true;
    user.verificationCode = null;
    user.verificationCodeExpires = null;

    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({ token });

  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ✅ LOGIN (ONLY IF VERIFIED)
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ error: "Invalid credentials" });

    if (!user.isVerified)
      return res.status(400).json({ error: "Please verify your email first" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid)
      return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({ token });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ------------------ AUTH MIDDLEWARE ------------------

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Missing token" });

  const token = auth.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ------------------ PROJECT ROUTES ------------------

// ✅ SAVE PROJECT
app.post("/saveProject", authMiddleware, upload.array("rasters"), async (req, res) => {
  try {
    const { layersJSON } = req.body;
    const rasterPaths = req.files ? req.files.map(f => f.path) : [];

    await User.findByIdAndUpdate(req.user.userId, {
      project: {
        layersJSON,
        rasterPaths,
        lastEdited: new Date()
      }
    });

    res.json({ message: "Project saved" });

  } catch (err) {
    console.error("Save error:", err);
    res.status(500).json({ error: "Error saving project" });
  }
});

// ✅ LOAD PROJECT
app.get("/loadProject", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user.project || !user.project.layersJSON)
      return res.status(404).json({ error: "No saved project" });

    res.json(user.project);

  } catch (err) {
    console.error("Load error:", err);
    res.status(500).json({ error: "Error loading project" });
  }
});

// Serve uploaded rasters
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ------------------ START SERVER ------------------

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
