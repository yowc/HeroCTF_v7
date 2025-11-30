
const { redirectWithFlash } = require('./utils/session');

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return redirectWithFlash(req, res, '/login', { type: 'error', message: 'Please log in.' });
  }
  next();
}

module.exports = { requireAuth };
