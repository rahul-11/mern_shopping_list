const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const config = require("config");
const jwt = require("jsonwebtoken");

// User Model
const User = require("../../models/User");

// @route   Post api/users
// @desc    Register user
// @access  Public
router.post("/", async (req, res) => {
  const { name, email, password } = req.body;

  // Simple validation
  if (!name || !email || !password) {
    res.status(400).json({ msg: "Please enter name, email, password" });
  }

  // Check existing user
  try {
    const user = await User.findOne({ email });
    if (user) {
      res.status(400).json({ msg: "User already exists" });
    }

    const newUser = new User({
      name,
      email,
      password
    });
    // Create salt and hash
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(newUser.password, salt);
    newUser.password = hash;
    await newUser.save();

    /**
     * jwt.sign(
     *  payload: what encrypted data you want to add,
     *  secret: the secret encryption key,
     *  additionOption: optional configuration sent with the payload to be encrypted into token,
     *  callback: you can use promises -> asynchronous
     * )
     */

    jwt.sign(
      { id: newUser._id },
      config.get("jwtSecret"),
      { expiresIn: 3600 },
      (err, token) => {
        if (err) throw err;
        res.status(200).json({
          token,
          user: { name: newUser.name, id: newUser._id, email: newUser.email }
        });
      }
    );
  } catch (err) {
    console.log(err);
  }
});

module.exports = router;
