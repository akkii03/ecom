const mongoose = require("mongoose");
const validator = require("validator");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "please enter your name"],
    maxLength: [30, "name can not exceed 30 char"],
    minLength: [4, "name should have more than 4 char"],
  },
  email: {
    type: String,
    required: [true, "please enter email"],
    unique: true,
    validate: [validator.isEmail, "please enter a valid email"],
  },
  phone: {
    type: Number,
    required: [true, "please enter phoneNumber"],
  },
  password: {
    type: String,
    required: [true, "please enter password"],
    minLength: [8, "password more than 8 char"],
    // select: false,
  },
  avatar: {
    public_id: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
  },
  role: {
    type: String,
    default: "user",
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
});

userSchema.methods.getResetToken = async function () {
  const resetToken = crypto.randomBytes(20).toString("hex");
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

    this.resetPasswordToken = Date.now()+15*60*1000
    return resetToken;
};

module.exports = mongoose.model("ecomuser", userSchema);
