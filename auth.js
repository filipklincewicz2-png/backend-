const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'secret-work-hours-token';
const TOKEN_EXPIRY = '7d';

function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function createToken(user) {
  return jwt.sign({ id: user.id, nick: user.nick }, JWT_SECRET, {
    expiresIn: TOKEN_EXPIRY,
  });
}

function getTokenFromRequest(req) {
  const authHeader = req.headers?.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  return req.cookies?.token || null;
}

function authenticateToken(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) {
    return res.status(401).json({ message: 'Brak tokena autoryzacji.' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      return res.status(401).json({ message: 'Nieudana autoryzacja.' });
    }
    req.user = payload;
    next();
  });
}

module.exports = {
  hashPassword,
  comparePassword,
  createToken,
  authenticateToken,
};
