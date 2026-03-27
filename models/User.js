const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  project: {
    layersJSON: String,
    rasterPaths: [String],
    lastEdited: Date
  }
});

module.exports = mongoose.model("User", userSchema);
