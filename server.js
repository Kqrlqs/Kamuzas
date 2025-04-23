const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: 'http://localhost:3000', // Pakeisk į savo frontend URL
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(bodyParser.json());

// MongoDB model
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  verified: { type: Boolean, default: false },
});
const User = mongoose.model('User', UserSchema);

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/kamuza', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Register
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    const url = `http://localhost:${PORT}/api/verify/${token}`;

    await transporter.sendMail({
      to: email,
      subject: 'Patvirtinkite savo paskyrą – Kamuza',
      html: `<h1>Sveiki, ${name}</h1><p>Spustelėkite šią nuorodą, kad patvirtintumėte paskyrą:</p><a href="${url}">${url}</a>`,
    });

    res.status(200).json({ message: 'Registracija sėkminga. Patikrinkite el. paštą.' });
  } catch (err) {
    res.status(400).json({ error: 'Vartotojo registracija nepavyko' });
  }
});

// Email verification
app.get('/api/verify/:token', async (req, res) => {
  try {
    const { email } = jwt.verify(req.params.token, process.env.JWT_SECRET);
    await User.updateOne({ email }, { verified: true });
    res.send('Paskyra patvirtinta! Galite prisijungti.');
  } catch (err) {
    res.status(400).send('Netinkama arba pasibaigusi nuoroda.');
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Vartotojas nerastas' });
    if (!user.verified) return res.status(401).json({ error: 'Paskyra nepatvirtinta' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Neteisingas slaptažodis' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ message: 'Prisijungta sėkmingai', token });
  } catch (err) {
    res.status(500).json({ error: 'Serverio klaida' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Serveris veikia: http://localhost:${PORT}`);
});
