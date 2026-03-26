const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// User model
const User = require("./models/User");

const app = express();
app.use(cors());
app.use(express.json());

// Multer setup for raster uploads
const upload = multer({ dest: "uploads/" });

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI; // store in Render env variables
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "replace_with_a_strong_secret";

// ------------------ AUTH ROUTES ------------------

// Sign up
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash });
    res.json({ message: "User created" });
  } catch (err) {
    res.status(400).json({ error: "User exists or invalid data" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// Middleware to verify token
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

// Save project
app.post("/project", authMiddleware, upload.array("rasters"), async (req, res) => {
  const { layersJSON } = req.body;
  const rasterPaths = req.files ? req.files.map(f => f.path) : [];
  try {
    await User.findByIdAndUpdate(req.user.userId, {
      project: { layersJSON, rasterPaths, lastEdited: new Date() }
    });
    res.json({ message: "Project saved" });
  } catch (err) {
    res.status(500).json({ error: "Error saving project" });
  }
});

// Load project
app.get("/project", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    res.json(user.project || {});
  } catch {
    res.status(500).json({ error: "Error loading project" });
  }
});

// Optional: serve uploaded rasters
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ------------------ START SERVER ------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
