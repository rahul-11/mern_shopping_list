const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const config = require("config");
const jwt = require("jsonwebtoken");

const auth = require("../../middleware/auth");

// User Model
const User = require("../../models/User");

// @route   Post api/auth
// @desc    Authenticate user
// @access  Public
router.post("/", async (req, res) => {
  const { email, password } = req.body;

  // Simple validation
  if (!email || !password) {
    res.status(400).json({ msg: "Please enter name, email, password" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "User doesn't exists" });
    }

    // Validating password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid password" });
    }
    jwt.sign(
      { id: user._id },
      config.get("jwtSecret"),
      { expiresIn: 3600 },
      (err, token) => {
        if (err) throw err;
        res.status(200).json({
          token,
          user: { name: user.name, id: user._id, email: user.email }
        });
      }
    );
  } catch (err) {
    console.log(err);
  }
});

// @route   Get api/auth/user
// @desc    get user data
// @access  Private
router.get("/user", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.status(200).json(user);
  } catch (err) {
    res.status(400).json({ msg: "No user found" });
  }
});

module.exports = router;
