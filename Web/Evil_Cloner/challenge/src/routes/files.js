
const express = require('express');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const { requireAuth } = require('../middleware');

const router = express.Router();

router.get('/', requireAuth, (req, res) => {
  let entries = [];
  let directory = req.session.user.clone_dir;
  entries = fs.readdirSync(directory).map(name => ({
    name
  }));
  res.render('files', { entries });
});

router.get('/download/:cloneName', requireAuth, (req, res) => {
  const rawName = req.params.cloneName;
  if (!rawName) return res.status(400).send('Clone name is required.');

  const safeName = path.basename(rawName);
  if (safeName !== rawName) {
    return res.status(400).send('Invalid clone name.');
  }

  const cloneRoot = req.session.user.clone_dir;
  let availableClones;
  try {
    availableClones = fs.readdirSync(cloneRoot, { withFileTypes: true })
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name);
  } catch (err) {
    console.error('Failed to list user clones:', err);
    return res.status(500).send('Unable to list clones for this account.');
  }

  if (!availableClones.includes(safeName)) {
    return res.status(404).send('Clone not found.');
  }

  const clonePath = path.join(cloneRoot, safeName);
  let stats;
  try {
    stats = fs.statSync(clonePath);
  } catch (err) {
    console.error('Failed to stat clone directory:', err);
    return res.status(404).send('Clone not found.');
  }

  if (!stats.isDirectory()) {
    return res.status(400).send('Clone is not a directory.');
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${safeName}.zip"`
  );

  const archive = archiver('zip', { zlib: { level: 9 } });

  archive.on('error', err => {
    console.error('Archive error:', err);
    if (!res.headersSent) {
      res.status(500).send('Failed to create archive.');
    } else {
      res.destroy(err);
    }
  });

  archive.pipe(res);
  archive.directory(clonePath, false);
  archive.finalize().catch(err => {
    console.error('Failed to finalize archive:', err);
    if (!res.headersSent) {
      res.status(500).send('Failed to create archive.');
    } else {
      res.destroy(err);
    }
  });
});

module.exports = router;
