const db = require('../config/db');
const bcrypt = require('bcrypt');

const User = {
  getAll: (callback) => {
    db.query('SELECT id, name, email FROM users', callback); 
  },

  getById: (id, callback) => {
    db.query('SELECT id, name, email FROM users WHERE id = ?', [id], callback);
  },

  getByEmail: (email, callback) => {
    db.query('SELECT * FROM users WHERE email = ?', [email], callback);
  },

  create: async (data, callback) => {
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(data.password, salt);
      const userData = { name: data.name, email: data.email, password: hashedPassword };
      db.query('INSERT INTO users SET ?', userData, callback);
    } catch (err) {
      callback(err);
    }
  },

  login: (email, password, callback) => {
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) return callback(err);
      if (results.length === 0) return callback(null, false); // user not found

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return callback(null, false); 

      delete user.password;
      callback(null, user);
    });
  },

  update: (id, data, callback) => {
    db.query('UPDATE users SET ? WHERE id = ?', [data, id], callback);
  },

  delete: (id, callback) => {
    db.query('DELETE FROM users WHERE id = ?', [id], callback);
  },
};

module.exports = User;
