const jwt = require('jsonwebtoken');
const User = require('../model/auth');

const JWT_SECRET = process.env.JWT_SECRET

exports.signup = (req, res) => {
  User.getByEmail(req.body.email, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    if (results.length > 0) return res.status(400).json({ message: 'Email already exists' });

    User.create(req.body, (err, result) => {
      if (err) return res.status(500).json({ error: err });
      res.status(201).json({ message: 'User registered', userId: result.insertId });
    });
  });
};

exports.login = (req, res) => {
  const { email, password } = req.body;
  User.login(email, password, (err, user) => {
    if (err) return res.status(500).json({ error: err });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token, user });
  });
};
