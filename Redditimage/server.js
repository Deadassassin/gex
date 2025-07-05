const express = require('express');
const path = require('path');
const fetch = require('node-fetch');
const os = require('os');
const WebSocket = require('ws');
const geoip = require('geoip-lite');
const si = require('systeminformation');
const cors = require('cors');
const http = require('http');
const bodyParser = require('body-parser');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const sharp = require('sharp');
const ffmpeg = require('fluent-ffmpeg');
const cheerio = require('cheerio');
const axios = require('axios');
const imageSize = require('image-size');
const puppeteer = require('puppeteer');
const { nanoid } = require('nanoid');
const useragent = require('useragent');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

const { LowSync } = require('lowdb');
const { JSONFileSync } = require('lowdb/node');

const shortenerAdapter = new JSONFileSync(path.join(__dirname, 'url-db.json'));
const shortenerDB = new LowSync(shortenerAdapter, { links: [] }); // ← default data here

shortenerDB.read();
shortenerDB.write(); // write if new

const CLIENT_ID = 'your-client-id-here';
const REDIRECT_URI = 'your-redirect-uri-here';
const USER_FILE = path.join(__dirname, 'chatreg.json');
let users = {};
if (fs.existsSync(USER_FILE)) {
  users = JSON.parse(fs.readFileSync(USER_FILE, 'utf8'));
}
const servers = {
  global: {
    name: 'Global Chat',
    channels: ['general'],
    members: [],
    createdAt: new Date().toISOString()
  }
};

const API_OPTIONS = {
  headers: {
    'User-Agent': 'Roblox/WinHttpClient',
    'Accept': 'application/json',
    'Referer': 'https://www.roblox.com/',
    'Origin': 'https://www.roblox.com',
    'Connection': 'keep-alive'
  }
};

const chatHistory = new Map();

const UPLOADS_DIR = path.join(__dirname, 'uploads');
const AVATARS_DIR = path.join(__dirname, 'public', 'uploads', 'avatars');

fs.mkdirSync(UPLOADS_DIR, { recursive: true });
fs.mkdirSync(AVATARS_DIR, { recursive: true });

function broadcastChatMessage(data, serverId = 'global') {
  if (!chatHistory.has(serverId)) {
    chatHistory.set(serverId, []);
  }
  
  const message = {
    ...data,
    serverId,
    id: crypto.randomBytes(16).toString('hex')
  };
  
  chatHistory.get(serverId).push(message);
  
  if (chatHistory.get(serverId).length > 1000) {
    chatHistory.get(serverId).shift();
  }
  
  activeChatUsers.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN && ws.serverId === serverId) {
      ws.send(JSON.stringify({ type: 'message', ...message }));
    }
  });
}

app.get('/chatsrvr/history/:serverId', (req, res) => {
  res.json(chatHistory.get(req.params.serverId) || []);
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const serverId = req.params.serverId || 'global';
    const dir = path.join(__dirname, 'uploads', serverId);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ storage });

app.post('/chatsrvr/upload/:serverId', upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) {
    return res
      .status(400)
      .json({ success: false, message: 'No file uploaded' });
  }

  try {
    const compressedPath = path.join(
      path.dirname(file.path),
      'compressed-' + file.filename
    );

    if (file.mimetype.startsWith('image/')) {
      await sharp(file.path)
        .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
        .jpeg({ quality: 80 })
        .toFile(compressedPath);

      fs.unlinkSync(file.path);
      file.path = compressedPath;
      file.size = fs.statSync(compressedPath).size;
    }

    const servedName = path.basename(compressedPath);
    res.json({
      success: true,
      url: `/uploads/${req.params.serverId}/${servedName}`,
      type: file.mimetype.split('/')[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Upload failed' });
  }
});

app.post('/chatsrvr/profile', (req, res) => {
  const { token, displayName, bio, color } = req.body;
  if (!token || !sessions.has(token)) return res.status(401).json({ success: false });

  const username = sessions.get(token);
  users[username].profile = {
    displayName: displayName || username,
    bio: bio || '',
    color: color || '#6c5ce7'
  };

  fs.writeFileSync(USER_FILE, JSON.stringify(users, null, 2));
  res.json({ success: true });
});

app.get('/chatsrvr/create-server', (req, res) => {
  const { serverId, token } = req.query;

  if (!token || !sessions.has(token)) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  if (!serverId || typeof serverId !== 'string' || serverId.includes(' ')) {
    return res.status(400).json({ success: false, message: 'Invalid server ID' });
  }

  if (servers[serverId]) {
    return res.json({ success: true, message: 'Server already exists' });
  }

  servers[serverId] = {
    name: `Server ${serverId}`,
    channels: ['general'],
    members: [],
    createdAt: new Date().toISOString()
  };

  res.json({ success: true });
});

app.get('/chatsrvr/profile/:username', (req, res) => {
  const { username } = req.params;

  if (!users[username]) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  const profile = users[username].profile || {
    displayName: username,
    avatar: null,
    bio: '',
    color: '#6c5ce7'
  };

  res.json({ success: true, profile });
});


// Middleware/Statics
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// WebSocket setup for monitoring
const monitoringWss = new WebSocket.Server({ noServer: true });
const monitoringClients = new Set();

monitoringWss.on('connection', (ws) => {
  monitoringClients.add(ws);
  ws.on('close', () => monitoringClients.delete(ws));
});

function broadcastMonitoringData(data) {
  const msg = JSON.stringify(data);
  for (const client of monitoringClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  }
}

const chatWss = new WebSocket.Server({ noServer: true });
const sessions = new Map();
const activeChatUsers = new Map();

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function broadcastServerUpdate(serverId) {
  const update = {
    type: 'server_update',
    serverId,
    server: servers[serverId]
  };
  
  activeChatUsers.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN && ws.serverId === serverId) {
      ws.send(JSON.stringify(update));
    }
  });
}

function broadcastChatUserList(serverId) {
  const usersInServer = Array.from(activeChatUsers.values())
    .filter(client => client.serverId === serverId)
    .map(client => client.username);
  
  const message = JSON.stringify({ 
    type: 'userlist',
    users: usersInServer,
    serverId
  });
  
  activeChatUsers.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN && ws.serverId === serverId) {
      ws.send(message);
    }
  });
}

function broadcastTypingIndicator(username, serverId) {
  activeChatUsers.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN && 
        ws.serverId === serverId && 
        ws.username !== username) {
      ws.send(JSON.stringify({
        type: 'typing',
        username,
        serverId
      }));
    }
  });
}

chatWss.on('connection', (ws, req) => {
  const scheme = req.headers['x-forwarded-proto'] === 'https' ? 'wss' : 'ws';
  const base   = `${scheme}://${req.headers.host}`;
  const url    = new URL(req.url, base);

  const token    = url.searchParams.get('token');
  const serverId = url.searchParams.get('server') || 'global';

  if (!token || !sessions.has(token)) {
    console.log('[WS CLOSE] Invalid token:', token);
    ws.close();
    return;
  }
  const username = sessions.get(token);
  ws.username   = username;
  ws.serverId   = serverId;

  if (!servers[serverId]) {
    servers[serverId] = {
      name:      `Server ${serverId}`,
      channels:  ['general'],
      members:   [],
      createdAt: new Date().toISOString()
    };
  }

  if (!servers[serverId].members.includes(username)) {
    servers[serverId].members.push(username);
    broadcastServerUpdate(serverId);
  }

  activeChatUsers.set(username, ws);
  broadcastChatUserList(serverId);

  ws.send(JSON.stringify({
    type:   'init',
    server: servers[serverId],
    user: {
      username,
      profile: users[username]?.profile || { displayName: username }
    }
  }));

  ws.on('message', (raw) => {
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return;
    }

    if (data.type === 'message') {
      broadcastChatMessage({
        username:  ws.username,
        text:      data.text,
        timestamp: new Date().toISOString()
      }, ws.serverId);

    } else if (data.type === 'typing') {
      broadcastTypingIndicator(ws.username, ws.serverId);

    } else if (data.type === 'file') {
      broadcastChatMessage({
        username:     ws.username,
        url:          data.url,
        fileType:     data.fileType,
        originalName: data.originalName,
        timestamp:    new Date().toISOString(),
        type:         'file'
      }, ws.serverId);
    }
  });
})

async function startLocalTrafficMonitoring() {
  try {
    const iface = await si.networkInterfaceDefault();
    setInterval(async () => {
      const [stats, conns] = await Promise.all([
        si.networkStats(iface),
        si.networkConnections()
      ]);
      broadcastMonitoringData({
        type: 'local_traffic',
        timestamp: new Date().toISOString(),
        interface: iface,
        rx_sec: (stats[0]?.rx_sec || 0).toFixed(2),
        tx_sec: (stats[0]?.tx_sec || 0).toFixed(2),
        activeConnections: conns.filter(c => c.state === 'ESTABLISHED').length,
        connections: conns.slice(0, 5)
      });
    }, 3000);
  } catch {
    console.warn('Could not start network monitoring');
  }
}

// Public feeds
function monitorPublicFeeds() {
  setInterval(async () => {
    try {
      const res = await fetch('https://hacker-news.firebaseio.com/v0/updates.json');
      const data = await res.json();
      broadcastMonitoringData({
        type: 'hacker_news_update',
        timestamp: new Date().toISOString(),
        items: data.items,
        profiles: data.profiles
      });
    } catch {}
  }, 10000);
}

app.use((req, res, next) => {
  broadcastMonitoringData({
    type: 'server_request',
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    ip: req.ip,
    headers: req.headers,
    query: req.query,
    body: req.body
  });
  next();
});

app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const geo = geoip.lookup(ip);
  if (geo) {
    broadcastMonitoringData({
      type: 'geolocation',
      timestamp: new Date().toISOString(),
      ip,
      country: geo.country,
      region: geo.region,
      city: geo.city,
      ll: geo.ll
    });
  }
  next();
});

app.get('/login', (req, res) => {
  const url = `https://www.reddit.com/api/v1/authorize?client_id=${CLIENT_ID}&response_type=code&state=random&redirect_uri=${REDIRECT_URI}&duration=permanent&scope=read identity`;
  res.redirect(url);
});

app.get('/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code');

  const auth = Buffer.from(`${CLIENT_ID}:`).toString('base64');
  try {
    const tokenRes = await fetch('https://www.reddit.com/api/v1/access_token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI
      })
    });
    const data = await tokenRes.json();
    if (data.error) return res.status(500).send(`OAuth error: ${data.error}`);

    const { access_token, refresh_token, expires_in } = data;
    res.redirect(`/loggedin.html#access_token=${access_token}&refresh_token=${refresh_token}&expires_in=${expires_in}`);
  } catch {
    res.status(500).send('OAuth token error');
  }
});

app.get('/refresh', async (req, res) => {
  const refresh_token = req.query.refresh_token;
  if (!refresh_token) return res.status(400).send('Missing refresh token');

  const auth = Buffer.from(`${CLIENT_ID}:`).toString('base64');
  try {
    const refreshRes = await fetch('https://www.reddit.com/api/v1/access_token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token
      })
    });
    const data = await refreshRes.json();
    if (data.error) return res.status(500).send(`Refresh error: ${data.error}`);

    res.json({ access_token: data.access_token, expires_in: data.expires_in });
  } catch {
    res.status(500).send('Token refresh failed');
  }
});

// Enhanced chat routes
app.post('/chatsrvr/register', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required' });
  }
  
  if (username.length < 3) {
    return res.json({ success: false, message: 'Username must be at least 3 characters' });
  }
  
  if (password.length < 6) {
    return res.json({ success: false, message: 'Password must be at least 6 characters' });
  }
  
  if (users[username]) {
    return res.json({ success: false, message: 'Username already exists' });
  }

users[username] = {
  password: hashPassword(password),
  createdAt: new Date().toISOString(),
  profile: {
    displayName: username,
    avatar: null,
    bio: '',
    color: '#6c5ce7'
  }
};

fs.writeFileSync(USER_FILE, JSON.stringify(users, null, 2));

app.post('/chatsrvr/avatar', upload.single('avatar'), async (req, res) => {
  const token = req.body.token;
  if (!token || !sessions.has(token)) return res.status(401).json({ success: false });
  
  const avatarPath = `/uploads/avatars/${username}.jpg`;
  
  try {
    await sharp(req.file.path)
      .resize(200, 200)
      .jpeg({ quality: 80 })
      .toFile(path.join(__dirname, 'public', avatarPath));
    
    users[username].profile.avatar = avatarPath;
    fs.writeFileSync(USER_FILE, JSON.stringify(users, null, 2));
    
    res.json({ success: true, avatar: avatarPath });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});
  
  // Save to file
  fs.writeFileSync(USER_FILE, JSON.stringify(users, null, 2));
  
  res.json({ success: true });
});

app.post('/chatsrvr/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  
  if (!user || user.password !== hashPassword(password)) {
    return res.json({ success: false, message: 'Invalid credentials' });
  }
  
  const token = generateToken();
  sessions.set(token, username);
  
  res.json({ 
    success: true, 
    token,
    username
  });
});

app.post('/shorten', (req, res) => {
  const { url } = req.body;
  if (!url || !url.startsWith('http')) {
    return res.status(400).json({ success: false, message: 'Invalid URL' });
  }

  const id = crypto.randomBytes(3).toString('hex'); // short code
  shortenerDB.data.links.push({ id, url, created: Date.now() });
  shortenerDB.write();

  res.json({ success: true, short: `${req.protocol}://${req.headers.host}/${id}` });
});


// Routes for static files
app.get('/support', (req, res) => res.sendFile(path.join(__dirname, 'public', 'support.html')));
app.get('/newtab', (req, res) => res.sendFile(path.join(__dirname, 'public', 'newtab.html')));
app.get('/experiences', (req, res) => res.sendFile(path.join(__dirname, 'public', 'experiences.html')));
app.get('/dj', (req, res) => res.sendFile(path.join(__dirname, 'public', 'simulation.html')));
app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, 'public', 'chat.html')));
app.get('/chtsignup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'chatsignup.html')));
app.get('/chtlogin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'chatlogin.html')));
app.get('/shorten', (req, res) => res.sendFile(path.join(__dirname, 'public', 'shorten.html')));

const queue = [];
let busy = false;

async function rateLimited(fn, retries = 3) {
  return new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject, retries });
    processQueue();
  });
}

async function processQueue() {
  if (busy || queue.length === 0) return;
  busy = true;

  const task = queue.shift();
  try {
    const res = await task.fn();
    if (res.status === 429 && task.retries > 0) {
      console.warn('429 Too Many Requests — retrying...');
      queue.unshift({ ...task, retries: task.retries - 1 });
    } else {
      task.resolve(res);
    }
  } catch (err) {
    task.reject(err);
  }

  setTimeout(() => {
    busy = false;
    processQueue();
  }, 500);
}

app.get('/api/roblox/:placeId', async (req, res) => {
  const placeId = req.params.placeId;
  const API_OPTIONS = {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Accept': 'application/json',
      'Origin': 'https://www.roblox.com'
    }
  };

  try {
    const universeRes = await fetch(`https://apis.roblox.com/universes/v1/places/${placeId}/universe`, API_OPTIONS);

    if (!universeRes.ok) {
      throw new Error(`Failed to fetch universe: ${universeRes.status} ${universeRes.statusText}`);
    }

    const universeData = await universeRes.json();
    const universeId = universeData.universeId;

    const [gameRes, thumbnailRes] = await Promise.all([
      rateLimited(() =>
        fetch(`https://games.roblox.com/v1/games?universeIds=${universeId}`, API_OPTIONS)
      ),
      rateLimited(() =>
        fetch(`https://thumbnails.roblox.com/v1/games/icons?universeIds=${universeId}&size=512x512&format=Png&isCircular=false`, API_OPTIONS)
      )
    ]);

    if (!gameRes.ok) {
      throw new Error(`Failed to fetch game details: ${gameRes.status} ${gameRes.statusText}`);
    }

    const gameData = await gameRes.json();
    const game = gameData.data?.[0] || {};

    let thumbnailUrl = 'https://via.placeholder.com/512x288/161616/999999?text=No+Thumbnail';
    if (thumbnailRes.ok) {
      const thumbnailData = await thumbnailRes.json();
      thumbnailUrl = thumbnailData.data?.[0]?.imageUrl || thumbnailUrl;
    }

    res.json({
      success: true,
      universeId,
      placeId,
      name: game.name || `Place ${placeId}`,
      playing: game.playing || 0,
      visits: game.visits || 0,
      favoritedCount: game.favoritedCount || 0,
      thumbnailUrl,
      updated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Roblox API error:', error.message);
    res.status(500).json({
      success: false,
      error: error.message,
      placeId
    });
  }
});

app.get('/api/roblox/games/all', async (req, res) => {
  const placeIds = [
    '5523486840',
    '155615604',
    '189707',
    '4520749081',
    '2753915549',
    '537413528',
    '6678877691'
  ];

  const games = [];
  let totalPlayers = 0;
  let trendingCount = 0;
  let popularCount = 0;
  let growthSum = 0;

  for (const placeId of placeIds) {
    try {
      const res = await fetch(`http://localhost:${PORT}/api/roblox/${placeId}`);
      const game = await res.json();
      if (!game.success) continue;

      const change = Math.floor(Math.random() * 21) - 10;
      const badge = game.playing > 50000
        ? 'popular'
        : change > 5
        ? 'trending'
        : Math.random() < 0.2
        ? 'new'
        : null;

      games.push({ ...game, placeId, change, badge, creator: 'Unknown', tags: ['fun', 'multiplayer'], creatorAvatar: '' });

      totalPlayers += game.playing;
      if (badge === 'trending') trendingCount++;
      if (badge === 'popular') popularCount++;
      growthSum += change;
    } catch (e) {
      console.warn(`Failed to load game ${placeId}:`, e.message);
    }
  }

  res.json({
    success: true,
    games,
    stats: {
      totalPlayers,
      trendingCount,
      popularCount,
      avgGrowth: (games.length > 0 ? Math.round(growthSum / games.length) : 0)
    }
  });
});

const IMGT_DIR = path.join(__dirname, 'downloads');
fs.mkdirSync(IMGT_DIR, { recursive: true });

async function downloadFile(fileUrl, savePath) {
  const writer = fs.createWriteStream(savePath);
  const response = await axios({ url: fileUrl, method: 'GET', responseType: 'stream' });
  response.data.pipe(writer);
  return new Promise((resolve, reject) => {
    writer.on('finish', resolve);
    writer.on('finish', () => {
      setTimeout(() => {
        fs.unlink(savePath, (err) => {
          if (err) console.warn(`Failed to delete ${path.basename(savePath)}:`, err.message);
          else console.log(`Deleted expired file: ${path.basename(savePath)}`);
        });
      }, 2 * 60 * 60 * 1000);
    });
    writer.on('error', reject);
  });
}

app.get('/:id', (req, res, next) => {
  const entry = shortenerDB.data.links.find(link => link.id === req.params.id);
  if (entry) {
    res.redirect(entry.url);
  } else {
    next();
  }
});


app.get('/imgtfile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'imgtfile.html'));
});

app.use('/downloads', express.static(path.join(__dirname, 'downloads')));


app.post('/imgtfile', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ success: false, message: 'No URL provided' });

  try {
    let response;
    try {
      response = await axios.get(url, {
        responseType: 'arraybuffer',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9'
        }
      });
    } catch (err) {
      if (err.response && err.response.status === 403) {
        console.warn('403 blocked. Switching to Puppeteer...');
        const puppeteerMedia = await (async function runPuppeteerFallback(url) {
  let mediaUrls = new Set();
let domUrls = [];
          const browser = await puppeteer.launch({ headless: 'new' });
          const page = await browser.newPage();
          await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115 Safari/537.36');
          await page.setViewport({ width: 1280, height: 800 });
                  
          await page.goto(url, { waitUntil: 'networkidle2', timeout: 80000 });
          await new Promise(res => setTimeout(res, 400));
          await autoScroll(page);

          async function autoScroll(page){
            await page.evaluate(async () => {
              await new Promise(resolve => {
                let totalHeight = 0;
                const distance = 100;
                const timer = setInterval(() => {
                  const scrollHeight = document.body.scrollHeight;
                  window.scrollBy(0, distance);
                  totalHeight += distance;
                  if(totalHeight >= scrollHeight){
                    clearInterval(timer);
                    resolve();
                  }
                }, 100);
              });
            });
          }
                  
          await page.evaluate(async () => {
            for (let i = 0; i < 10; i++) {
              window.scrollBy(0, window.innerHeight);
              await new Promise(r => setTimeout(r, 1000));
            }
          });

          mediaUrls =await page.evaluate(() => {
            const urls = [];
            document.querySelectorAll('img, video, source').forEach(el => {
              const src = el.src || el.getAttribute('data-src');
              if (src && !src.startsWith('data:')) urls.push(src);
            });
            return urls;
          });

          await browser.close();

          const found = [];
          for (let src of mediaUrls) {
            if (src.startsWith('data:')) continue;
            try {
              let absUrl = new URL(src, url).href;
            
              // Handle Next.js image proxy (/_next/image)
              const parsed = new URL(absUrl);
              if (parsed.pathname === '/_next/image' && parsed.searchParams.has('url')) {
                const realPath = parsed.searchParams.get('url');
                if (realPath) {
                  absUrl = new URL(realPath, url).href;
                }
              }
            
              const hash = crypto.createHash('md5').update(absUrl).digest('hex');
              const ext = path.extname(new URL(absUrl).pathname) || '.jpg';
              const fileName = `${hash}${ext}`;
              const fullPath = path.join(IMGT_DIR, fileName);
              await downloadFile(absUrl, fullPath);
              found.push({ file: fileName, from: `/downloads/${fileName}` });
            } catch (e) {
              console.warn('Invalid Puppeteer src:', src);
            }
          }

          return found;
        })(url);

        if (puppeteerMedia.length > 0) {
          return res.json({ success: true, count: puppeteerMedia.length, media: puppeteerMedia });
        } else {
          return res.json({ success: false, message: 'No media found using Puppeteer either.' });
        }
      } else {
        console.error('Axios failed:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }
    }

    const contentType = response.headers['content-type'];
    const media = [];

    if (contentType.startsWith('image/') || contentType.startsWith('video/')) {
      const urlPath = new URL(url).pathname;
      let fileName = path.basename(urlPath);
      let ext = path.extname(fileName);

      const typeMap = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif',
        'image/webp': '.webp',
        'image/bmp': '.bmp',
        'image/svg+xml': '.svg',
        'video/mp4': '.mp4',
        'video/webm': '.webm',
        'video/ogg': '.ogv',
        'video/x-msvideo': '.avi'
      };

      if (!ext || !Object.values(typeMap).includes(ext.toLowerCase())) {
        ext = typeMap[contentType] || '';
        const baseName = path.basename(urlPath).split('.')[0];
        fileName = baseName + ext;
      }

      const fullPath = path.join(IMGT_DIR, fileName);
      fs.writeFileSync(fullPath, response.data);
      setTimeout(() => {
        fs.unlink(fullPath, (err) => {
          if (err) console.warn(`Failed to delete ${fileName}:`, err.message);
          else console.log(`Deleted expired file: ${fileName}`);
        });
      }, 2 * 60 * 60 * 1000);
      let dimensions = {};
      try {
        dimensions = imageSize(response.data);
      } catch (e) {
        console.warn('Failed to read image dimensions:', e.message);
      }
      media.push({
        file: fileName,
        from: `/downloads/${fileName}`,
        size: response.data.length,
        dimensions
      });
      return res.json({ success: true, count: 1, media });
    }

    const html = response.data.toString('utf-8');
    const $ = cheerio.load(html);

    $('img, video, source').each((_, el) => {
      let src = $(el).attr('src') || $(el).attr('data-src');
      if (!src || src.startsWith('data:')) return;
      try {
        const absUrl = new URL(src, url).href;
        const hash = crypto.createHash('md5').update(absUrl).digest('hex');
        const ext = path.extname(new URL(absUrl).pathname) || '.jpg';
        const fileName = `${hash}${ext}`;
        const fullPath = path.join(IMGT_DIR, fileName);
        media.push({ file: fileName, from: `/downloads/${fileName}` });
        downloadFile(absUrl, fullPath);
      } catch (e) {
        console.warn('Invalid src:', src);
      }
    });

    return res.json({ success: true, count: media.length, media });
  } catch (err) {
    console.error('Scrape failed:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/shortened-urls', (req, res) => {
  shortenerDB.read(); // Ensure it's fresh
  res.json({ success: true, links: shortenerDB.data.links });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
  startLocalTrafficMonitoring();
  monitorPublicFeeds();
});

server.on('upgrade', (req, socket, head) => {
  const pathname = new URL(req.url, `http://${req.headers.host}`).pathname; // <-- FIX

  if (pathname === '/chatsrvr') {
    chatWss.handleUpgrade(req, socket, head, ws => {
      chatWss.emit('connection', ws, req);
    });
  } else {
    socket.destroy();
  }
});

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}
