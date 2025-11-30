
const express = require('express');
const { requireAuth } = require('../middleware');
const { cloneWebsite } = require('../services/cloner');
const { checkSiteAvailability } = require('../services/bot');
const { setFlash } = require('../utils/session');
const path = require("path");
const fs = require("fs");
const dns = require('dns').promises;

const router = express.Router();

router.get('/', requireAuth, async (req, res) => {
  res.render('clone');
});

router.post('/run', requireAuth, async (req, res) => {
  const { url } = req.body;
  let flash;
  try {
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      flash = { type: 'error', message: 'Invalid URL.' };
    } else {
      const { host, hostname } = new URL(url);
      await dns.lookup(hostname);
      const userCloneDir = path.join(req.session.user.clone_dir, host);
      fs.mkdirSync(userCloneDir, { recursive: true });
      const success = await cloneWebsite(url, userCloneDir);
      flash = success
        ? { type: 'success', message: 'Website has been cloned !' }
        : { type: 'error', message: 'An error occured while cloning the website.' };
    }
  } catch (e) {
    flash = { type: 'error', message: 'An error occured.' };
  }
  if (flash) {
    try {
      await setFlash(req, flash);
    } catch (err) {
      console.error('Failed to persist flash message:', err);
    }
  }
  return res.redirect('/clone');
});

router.post('/check', requireAuth, async (req, res) => {
  const { url } = req.body;
  let flash;
  try {
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
      flash = { type: 'error', message: 'Invalid URL.' };
    } else {
      const { hostname } = new URL(url);
      await dns.lookup(hostname);
      const reachable = await checkSiteAvailability(url, req.session.user.data_dir);
      flash = reachable
        ? { type: 'success', message: 'Recon bot reports we are not banned from this target.' }
        : { type: 'error', message: 'Recon bot could not reach the target. We may be banned.' };
    }
  } catch (e) {
    flash = { type: 'error', message: 'Failed to run the ban check.' };
  }
  if (flash) {
    try {
      await setFlash(req, flash);
    } catch (err) {
      console.error('Failed to persist flash message:', err);
    }
  }
  return res.redirect('/clone');
});

module.exports = router;
