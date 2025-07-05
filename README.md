# Gex

Gex is a full-stack Node.js app for URL shortening, media scraping, file downloading, and more. It includes optional real-time chat and system monitoring.

---

## ⚠️ Reddit API Setup (Required)

To enable Reddit login, you must edit `server.js`.

### Steps:

1. Go to [https://www.reddit.com/prefs/apps](https://www.reddit.com/prefs/apps)

2. Click **Create App**, choose `installed app`

3. Fill in:
   - **Name**: Anything
   - **Redirect URI**:  
     ```
     http://localhost:8080
     ```

4. Click **Create App**

5. Copy the **client ID**

6. In `server.js`, find the Reddit section and set:
   ```js
   const CLIENT_ID = 'your-client-id-here';
   const REDIRECT_URI = 'http://localhost:8080';
### Required Dependencies:
1. Made simple copy and paste
```
npm install express path node-fetch os ws geoip-lite systeminformation cors http body-parser fs crypto multer sharp fluent-ffmpeg cheerio axios image-size puppeteer nanoid useragent
```
2. Then required apps
Install these system-level apps:

Node.js + npm – runs the server

ffmpeg – for video processing

Chromium or Google Chrome – required for Puppeteer scraping

Install on Debian/Ubuntu:
```
sudo apt update
sudo apt install nodejs npm ffmpeg chromium
```
Install on Arch:
```
sudo pacman -S nodejs npm ffmpeg chromium
```
