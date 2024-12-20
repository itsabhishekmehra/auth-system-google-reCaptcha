const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Rate limiting middleware for login route
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts. Please try again later.',
});

// PostgreSQL Client
const { Pool } = require('pg');
const db = new Pool({
  connectionString: process.env.DB_URL,
});

// Routes
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || password.length < 8) {
    return res.render('register', { error: 'Invalid input data' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
    );
    res.render('login', { message: 'Registration successful. Please log in.' });
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Registration failed. Try again.' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { siteKey: process.env.RECAPTCHA_SITE_KEY });
});

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password, 'g-recaptcha-response': recaptchaToken } = req.body;

  // Verify Google reCAPTCHA
  const recaptchaURL = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`;
  const recaptchaResponse = await fetch(recaptchaURL, { method: 'POST' }).then((res) => res.json());
  if (!recaptchaResponse.success) {
    return res.render('login', { error: 'Invalid reCAPTCHA. Please try again.' });
  }

  try {
    const userQuery = 'SELECT * FROM users WHERE username = $1';
    const user = await db.query(userQuery, [username]);

    if (user.rows.length === 0) {
      return res.render('login', { error: 'User not found.' });
    }

    const isMatch = await bcrypt.compare(password, user.rows[0].password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { id: user.rows[0].id, username: user.rows[0].username, email: user.rows[0].email, exp: Math.floor(Date.now() / 1000) + 15 * 60 },
      process.env.JWT_SECRET
    );

    res.cookie('token', token, { httpOnly: true });
    res.redirect('/profile');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Login failed. Try again.' });
  }
});

app.get('/profile', (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.render('profile', { user });
  } catch (err) {
    console.error(err);
    res.clearCookie('token');
    res.redirect('/login');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
