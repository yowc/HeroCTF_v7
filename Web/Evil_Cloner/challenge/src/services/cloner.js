const path = require('path');
const fs = require('fs/promises');
const cheerio = require('cheerio');
const URLParse = require("url-parse");

function filenameFromHeaders(headers) {
  const cd = headers.get('content-disposition');
  if (!cd) return null;
  const filenameStar = cd.match(/filename\*\s*=\s*([^']*)''([^;]+)/i);
  if (filenameStar && filenameStar[2]) {
    try {
      return decodeURIComponent(filenameStar[2]);
    } catch {
      return filenameStar[2];
    }
  }
  const filenameQuoted = cd.match(/filename\s*=\s*"([^"]+)"/i);
  if (filenameQuoted && filenameQuoted[1]) {
    return filenameQuoted[1];
  }
  const filenameBare = cd.match(/filename\s*=\s*([^;]+)/i);
  if (filenameBare && filenameBare[1]) {
    return filenameBare[1].trim();
  }
  return null;
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

function isHttpUrl(u) {
  try {
    const { protocol } = new URLParse(u);
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
}

async function downloadToFile(resourceUrl, destPath, controller) {
  const res = await fetch(resourceUrl, {
    redirect: 'follow',
    signal: controller?.signal,
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; EvilCloner/1.0)' },
  });
  if (!res.ok) {
    return false;
  }

  let finalPath = destPath;
  const headerName = filenameFromHeaders(res.headers);
  if (headerName) {
    finalPath = path.dirname(destPath)+"/"+headerName;
  }
  if(finalPath.includes("..")) {
    return false;
  }
  const buf = Buffer.from(await res.arrayBuffer());
  finalPath = new URLParse(finalPath).pathname;
  if(finalPath == false) {
    return false;
  }
  await fs.writeFile(finalPath, buf);
  return true;
}

async function fetchWithTimeout(url, ms) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; EvilCloner/1.0)' },
    });
    return res;
  } finally {
    clearTimeout(t);
  }
}

async function cloneWebsite(targetUrl, userCloneDir) {
  await ensureDir(userCloneDir);

  const res = await fetchWithTimeout(targetUrl, 15000);
  if (!res.ok) return false;
  const html = await res.text();
  const $ = cheerio.load(html);
  const urls = new Set();

  $('img[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (!src) return;
    try {
      const abs = new URLParse(src, targetUrl).toString();
      if (isHttpUrl(abs)) urls.add(abs);
    } catch {}
  });

  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (!src) return;
    try {
      const abs = new URLParse(src, targetUrl).toString();
      if (isHttpUrl(abs)) urls.add(abs);
    } catch {}
  });

  const toDownload = Array.from(urls).slice(0, 5);
  for (const file of toDownload) {
    try {
      if (file.endsWith('/')) {
        realPath += 'index.html';
      }
      let remote_path = new URL(file);
      const finalPath = path.join(userCloneDir, remote_path.pathname);
      
      await ensureDir(path.dirname(finalPath));
      await downloadToFile(file, finalPath);
    } catch {}
  }

  return true;
}

module.exports = { cloneWebsite };