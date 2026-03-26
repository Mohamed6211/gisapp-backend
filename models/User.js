const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  project: {
    layersJSON: String,      // Leaflet layers as JSON
    rasterPaths: [String],   // uploaded rasters
    lastEdited: Date
  }
});

module.exports = mongoose.model("User", UserSchema);
