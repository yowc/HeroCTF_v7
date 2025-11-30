const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const URL = process.env.WEBAPP;
const ADMINPASS = process.env.ADMINPASS;

// --- Logger Setup ---
const logFilePath = '/home/pptruser/bot.log';
const logDir = path.dirname(logFilePath);

// Ensure the log directory exists
try {
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
    }
} catch (e) {
    console.error(`FATAL: Could not create log directory at ${logDir}. Error: ${e.message}`);
    process.exit(1);
}

// Create a writable stream to the log file
const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });

// Custom log function to write to both file and console
const log = {
    info: (message) => logMessage('INFO', message),
    warn: (message) => logMessage('WARN', message),
    error: (message) => logMessage('ERROR', message),
};

function logMessage(level, message) {
    const timestamp = new Date().toISOString();
    const formattedMessage = `${timestamp} [${level}]: ${message}\n`;
    process.stdout.write(formattedMessage); // Keep console output for container logs
    logStream.write(formattedMessage);
}
// --- End Logger Setup ---

async function runBot() {
    log.info('Bot starting...');
    let browser;

    try {
        // Launch Puppeteer with recommended arguments for Docker containers
        browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--no-zygote'
            ],
        });

        const page = await browser.newPage();

        // --- Login Step ---
        log.info(`Navigating to ${URL}/login to log in as 'saruman'`);
        await page.goto(`${URL}/login`, { waitUntil: 'networkidle0' });

        // Interact with the login form directly to preserve session storage
        log.info('Filling out login form...');
        await page.type('input[name="username"]', 'saruman');
        await page.type('input[name="password"]', ADMINPASS);
        
        log.info('Submitting login form...');
        // We'll click the submit button and wait for navigation to complete.
        // This ensures the page has processed the login and redirected.
        await Promise.all([
            page.waitForNavigation({ waitUntil: 'networkidle0' }),
            page.click('button[type="submit"]') // Adjust selector if needed
        ]);
        
        // Verify login was successful by checking the URL or for a specific element
        if (page.url() === `${URL}/` || page.url() === URL) {
            log.info('Login successful. Landed on the main application page.');
        } else {
             log.error(`Login failed. Current URL is ${page.url()}`);
             throw new Error('Login failed, aborting bot.');
        }

        // --- Main Interaction Loop ---
        // The bot is now on the main page with the session active.
        while (true) {
            try {
                log.info('Starting interaction cycle...');

                // 1. Click on the "Request FLAG" button
                log.info('Searching for "Request FLAG" button...');
                const requestButton = await page.waitForSelector("xpath///button[contains(., 'Request FLAG')]", { timeout: 10000 });
                if (requestButton) {
                    log.info('"Request FLAG" button found. Clicking now.');
                    await requestButton.click();

                    // 2. Wait for the "Decrypt" button to appear and click it
                    log.info('Searching for "Decrypt" button...');
                    const decryptButton = await page.waitForSelector("xpath///button[contains(., 'Decrypt')]", { visible: true, timeout: 10000 });
                    if (decryptButton) {
                        log.info('"Decrypt" button appeared. Clicking now.');
                        await decryptButton.click();
                        log.info('Successfully decrypted the flag.');
                    } else {
                        log.warn('"Decrypt" button did not appear within 10 seconds.');
                    }
                } else {
                    log.warn('"Request FLAG" button not found.');
                }

            } catch (e) {
                log.error(`An error occurred during the interaction loop: ${e.message}`);
                // Attempt to recover by reloading the page for the next cycle
                try {
                    log.info('Attempting to reload the page to recover from the error...');
                    await page.reload({ waitUntil: 'networkidle0' });
                    log.info('Page reloaded successfully.');
                } catch (reloadError) {
                    log.error(`Failed to reload page after error: ${reloadError.message}`);
                    // If reload fails, it's a critical error.
                    throw new Error('Could not recover by reloading page. Aborting.');
                }
            }
            
            // Wait for 30 seconds before starting the next cycle.
            log.info('Waiting for 30 seconds...');
            await new Promise(resolve => setTimeout(resolve, 30000));
        }

    } catch (error) {
        log.error(`A critical error occurred in the bot: ${error.message}`);
    } finally {
        if (browser) {
            log.info('Closing browser.');
            await browser.close();
        }
        log.info('Bot shutting down.');
        logStream.end(); // Close the file stream
    }
}

runBot();
