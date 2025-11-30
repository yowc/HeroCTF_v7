const express = require('express');
const bcrypt = require('bcryptjs');
const { createUser, findUserByUsername } = require('../db');
const { requireAuth } = require('../middleware');
const { setFlash, redirectWithFlash, saveSession } = require('../utils/session');

const router = express.Router();

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/clone');
  res.render('login');
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await findUserByUsername(username);
  if (!user) {
    await redirectWithFlash(req, res, '/login', { type: 'error', message: 'Invalid credentials.' });
    return;
  }
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    await redirectWithFlash(req, res, '/login', { type: 'error', message: 'Invalid credentials.' });
    return;
  }

  try {
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => (err ? reject(err) : resolve()));
    });
  } catch {
    await redirectWithFlash(req, res, '/login', { type: 'error', message: 'Session error, please try again.' });
    return;
  }

  req.session.user = { id: user.id, username: user.username, data_dir: user.data_dir, clone_dir: user.clone_dir };

  try {
    await saveSession(req);
  } catch {
    await redirectWithFlash(req, res, '/login', { type: 'error', message: 'Session error, please try again.' });
    return;
  }

  return res.redirect('/clone');
});

router.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/clone');
  res.render('register');
});

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    await redirectWithFlash(req, res, '/register', { type: 'error', message: 'Missing fields.' });
    return;
  }
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);
  try {
    const created = await createUser(username, hash);
    try {
      await setFlash(req, { type: 'success', message: 'User created.', user: created });
    } catch (err) {
      console.error('Failed to persist flash message:', err);
    }
    return res.redirect('/login');
  } catch (e) {
    await redirectWithFlash(req, res, '/register', { type: 'error', message: 'An error occured while creating your account.' });
  }
});

router.get('/me', requireAuth, (req, res) => {
  res.json(req.session.user);
})

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

module.exports = router;
