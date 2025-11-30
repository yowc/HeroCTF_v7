FROM ghcr.io/puppeteer/puppeteer:22.12.1

WORKDIR /home/pptruser
COPY package.json package-lock.json* ./
COPY bot.js .
RUN npm install

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome

CMD ["npm", "start"]