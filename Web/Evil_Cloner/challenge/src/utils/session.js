function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

async function setFlash(req, flash) {
  req.session.flash = flash;
  await saveSession(req);
}

async function redirectWithFlash(req, res, url, flash) {
  try {
    await setFlash(req, flash);
  } catch (err) {
    console.error('Failed to persist flash message:', err);
  }
  return res.redirect(url);
}

module.exports = { saveSession, setFlash, redirectWithFlash };
