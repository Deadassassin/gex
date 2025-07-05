const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
const PORT = 8081;

const IMGT_DIR = path.join(__dirname, 'downloads');
fs.mkdirSync(IMGT_DIR, { recursive: true });

app.use('/downloads', express.static(IMGT_DIR));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/imgtfile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'imgtfile.html'));
});

async function downloadFile(fileUrl, savePath) {
  const writer = fs.createWriteStream(savePath);
  const response = await axios({ url: fileUrl, method: 'GET', responseType: 'stream' });
  response.data.pipe(writer);
  return new Promise((resolve, reject) => {
    writer.on('finish', resolve);
    writer.on('error', reject);
    writer.on('close', () => {
      setTimeout(() => {
        fs.unlink(savePath, (err) => {
          if (!err) console.log('Deleted expired file:', savePath);
        });
      }, 2 * 60 * 60 * 1000);
    });
  });
}

async function autoScroll(page) {
  let previousHeight = await page.evaluate('document.body.scrollHeight');
  while (true) {
    await page.evaluate('window.scrollTo(0, document.body.scrollHeight)');
    await new Promise(resolve => setTimeout(resolve, 2000));
    const newHeight = await page.evaluate('document.body.scrollHeight');
    if (newHeight === previousHeight) break;
    previousHeight = newHeight;
  }
}

app.post('/imgtfile', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ success: false, message: 'No URL provided' });

  const media = new Set();
  try {
    const browser = await puppeteer.launch({ headless: 'new' });
    const page = await browser.newPage();

    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
    await page.setRequestInterception(true);

    page.on('request', (req) => {
      if (['image', 'stylesheet', 'font'].includes(req.resourceType())) req.abort();
      else req.continue();
    });

    page.on('response', async (response) => {
      const reqUrl = response.url();
      if (reqUrl.includes('yandex.com/images-api/') && response.request().resourceType() === 'xhr') {
        try {
          const json = await response.json();
          json?.blocks?.forEach(block => {
            const src = block?.image?.url;
            if (src && !src.startsWith('data:')) media.add(src);
          });
        } catch {}
      }
    });

    await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });
    await autoScroll(page);
    await new Promise(r => setTimeout(r, 5000));

    const domUrls = await page.evaluate(() => {
      const urls = [];
      document.querySelectorAll('img, video, source').forEach(el => {
        const src = el.src || el.getAttribute('data-src');
        if (src && !src.startsWith('data:')) urls.push(src);
      });
      return urls;
    });

    domUrls.forEach(u => media.add(u));
    await browser.close();

    const result = [];

    for (const src of media) {
      try {
        const absUrl = new URL(src, url).href;
        const hash = crypto.createHash('md5').update(absUrl).digest('hex');
        const ext = path.extname(new URL(absUrl).pathname) || '.jpg';
        const fileName = `${hash}${ext}`;
        const fullPath = path.join(IMGT_DIR, fileName);
        await downloadFile(absUrl, fullPath);
        result.push({ file: fileName, from: `/downloads/${fileName}` });
      } catch (err) {
        console.warn('Invalid media URL:', src);
      }
    }

    if (result.length === 0) {
      return res.json({ success: false, message: 'No media found.' });
    }

    return res.json({ success: true, count: result.length, media: result });

  } catch (err) {
    console.error('Scrape failed:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
