const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  passwordHash: String,

  isVerified: { type: Boolean, default: false },
  verificationCode: String,
  verificationCodeExpires: Date,

  project: {
    layersJSON: String,
    rasterPaths: [String],
    lastEdited: Date
  }
});

module.exports = mongoose.model("User", userSchema);
