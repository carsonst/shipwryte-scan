const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mysql = require('mysql2');

const app = express();

// CORS wildcard - common AI code pattern
app.use(cors({ origin: "*", credentials: true }));

const JWT_SECRET = "mysecretkey123";

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'admin123',
  database: 'myapp'
});

// SQL injection vulnerability
app.get('/users', (req, res) => {
  const search = req.query.search;
  db.query(`SELECT * FROM users WHERE name = '${search}'`, (err, results) => {
    res.json(results);
  });
});

// No password hashing
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  db.query('INSERT INTO users SET ?', { username, password: req.body.password }, (err) => {
    if (err) return res.status(500).json({ error: 'Registration failed' });
    res.json({ success: true });
  });
});

// Weak JWT
app.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.username }, "secret");
  res.json({ token });
});

// Open redirect
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// Exposed debug route
app.get('/debug/users', (req, res) => {
  db.query('SELECT * FROM users', (err, results) => {
    res.json(results);
  });
});

// Eval usage
app.post('/calculate', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// Command injection
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3000);
