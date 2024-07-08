const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  idDocument: { type: String, required: true },
});

module.exports = mongoose.model('User', userSchema);
// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const User = require('../models/User');
const router = express.Router();
const upload = multer({ dest: 'uploads/' });

// Validate email and phone
const validateEmail = (email) => {
  const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(([^<>()[\]\\.,;:\s@"]+\.)+[^<>()[\]\\.,;:\s@"]{2,})$/i;
  return re.test(String(email).toLowerCase());
};

const validatePhone = (phone) => {
  const re = /^\+20[0-9]{9}$/;
  return re.test(String(phone));
};

router.post('/signup', upload.single('idDocument'), async (req, res) => {
  const { fullName, email, phone, password } = req.body;

  if (!validateEmail(email) || !validatePhone(phone)) {
    return res.status(400).send('Invalid email or phone format');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({
    fullName,
    email,
    phone,
    password: hashedPassword,
    idDocument: req.file.path,
  });

  await user.save();

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: 'Verify your email',
    text: `Click on this link to verify your email: ${process.env.BASE_URL}/auth/verify/${token}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return res.status(500).send('Error sending email');
    }
    res.status(201).send('User registered successfully');
  });
});

router.get('/verify/:token', async (req, res) => {
  try {
    const { email } = jwt.verify(req.params.token, process.env.JWT_SECRET);
    await User.updateOne({ email }, { isVerified: true });
    res.status(200).send('Email verified successfully');
  } catch (error) {
    res.status(400).send('Invalid or expired token');
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(400).send('Invalid email or password');
  }

  if (!user.isVerified) {
    return res.status(403).send('Account not verified');
  }

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

  res.status(200).send({ token });
});

module.exports = router;
