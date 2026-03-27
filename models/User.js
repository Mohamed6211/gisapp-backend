const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },

  // ✅ Email verification
  isVerified: { type: Boolean, default: false },
  verificationCode: String,
  verificationCodeExpires: Date,

  // ✅ Project storage (ONLY ONE project per user)
  project: {
    layersJSON: { type: String, default: null },
    rasterPaths: { type: [String], default: [] },
    lastEdited: { type: Date, default: null }
  }
});

module.exports = mongoose.model("User", userSchema);
