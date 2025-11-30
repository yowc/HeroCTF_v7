const path = require('path');
const fs = require('fs/promises');
const puppeteer = require('puppeteer');

async function checkSiteAvailability(targetUrl, userDirCode) {
  process.env.HOME = "/tmp/";

  const args = [
    "--disable-dev-shm-usage",
    "--no-sandbox"
  ];

  const profileCode = userDirCode || 'shared';
  const userDataDir = path.join('/tmp/profiles', profileCode);
  await fs.mkdir(userDataDir, { recursive: true });
  args.push(`--user-data-dir=${userDataDir}`);

  const browser = await puppeteer.launch({
    headless: 'new',
    executablePath: "/usr/bin/google-chrome",
    args,
    ignoreDefaultArgs: ["--disable-client-side-phishing-detection", "--disable-component-update", "--force-color-profile=srgb"]
  });

  const page = await browser.newPage();
  page.setDefaultNavigationTimeout(15000);

  try {
    console.log("[BOT] - Checking if target banned us…");
    const response = await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
    const status = response?.status() ?? 0;
    return status >= 200 && status < 400;
  } catch (error) {
    console.error("[BOT] - Failed to reach target:", error.message);
    return false;
  } finally {
    await browser.close();
  }
}

module.exports = { checkSiteAvailability };
