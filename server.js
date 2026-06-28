const express    = require('express');
const fetch      = require('node-fetch');
const cors       = require('cors');
const path       = require('path');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Database   = require('better-sqlite3');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'tradesmart-secret-2025';
const STRIPE_KEY  = process.env.STRIPE_KEY  || '';
const EMAIL_USER  = process.env.EMAIL_USER  || '';
const EMAIL_PASS  = process.env.EMAIL_PASS  || '';
const PRICE_ID    = process.env.STRIPE_PRICE_ID || '';

// ── DB SQLITE ─────────────────────────────────────────────
const db = new Database('./tradesmart.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    plan TEXT DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    watchlist TEXT DEFAULT '["AAPL","MSFT","GOOGL","AMZN","NVDA","META","TSLA","SPY","F"]',
    alerts_enabled INTEGER DEFAULT 1,
    drop_alert REAL DEFAULT 5.0,
    whatsapp_phone TEXT DEFAULT NULL,
    whatsapp_apikey TEXT DEFAULT NULL,
    whatsapp_enabled INTEGER DEFAULT 0,
    telegram_chat_id TEXT DEFAULT NULL,
    telegram_enabled INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  );
`);

// Migrar columnas si ya existe la tabla
try { db.exec('ALTER TABLE users ADD COLUMN whatsapp_phone TEXT DEFAULT NULL'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN whatsapp_apikey TEXT DEFAULT NULL'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN whatsapp_enabled INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN telegram_chat_id TEXT DEFAULT NULL'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN telegram_enabled INTEGER DEFAULT 0'); } catch(e) {}

// ── MIDDLEWARE ────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// Plan middleware
function proMiddleware(req, res, next) {
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
  if (user?.plan !== 'pro') {
    return res.status(403).json({ error: 'Plan Pro requerido', upgrade: true });
  }
  next();
}

// ── AUTH ROUTES ───────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)');
    const result = stmt.run(email, hash, name || email.split('@')[0]);
    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '30d' });
    sendWelcomeEmail(email, name || email.split('@')[0]);
    res.json({ ok: true, token, user: { id: result.lastInsertRowid, email, name, plan: 'free' } });
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email ya registrado' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Contraseña incorrecta' });
  db.prepare('UPDATE users SET last_login = datetime("now") WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ ok: true, token, user: { id: user.id, email: user.email, name: user.name, plan: user.plan } });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, email, name, plan, watchlist, alerts_enabled, drop_alert, whatsapp_phone, whatsapp_apikey, whatsapp_enabled FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  user.watchlist = JSON.parse(user.watchlist || '[]');
  res.json({ ok: true, user });
});

// ── WATCHLIST ─────────────────────────────────────────────
app.post('/api/watchlist', authMiddleware, (req, res) => {
  const { tickers } = req.body;
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
  const max = user.plan === 'pro' ? 50 : 5;
  if (tickers.length > max) return res.status(403).json({ error: `Plan Free: máximo ${max} acciones. Actualiza a Pro para más.`, upgrade: true });
  db.prepare('UPDATE users SET watchlist = ? WHERE id = ?').run(JSON.stringify(tickers), req.user.id);
  res.json({ ok: true });
});

// ── STOCK DATA — YAHOO FINANCE ────────────────────────────
app.get('/api/stock/:ticker', authMiddleware, async (req, res) => {
  const { ticker } = req.params;
  try {
    const url  = `https://query1.finance.yahoo.com/v8/finance/chart/${ticker}?interval=1d&range=2y`;
    const resp = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 });
    const json = await resp.json();
    if (!json.chart?.result?.length) return res.status(404).json({ error: 'Ticker no encontrado: ' + ticker });
    const r = json.chart.result[0];
    const meta = r.meta;
    const q = r.indicators.quote[0];
    const closes  = q.close.filter(v => v != null);
    const volumes = q.volume.filter(v => v != null);
    const price     = meta.regularMarketPrice || closes[closes.length-1];
    const prevClose = meta.previousClose || meta.chartPreviousClose;
    const changeDay = ((price - prevClose) / prevClose) * 100;
    const max20   = Math.max(...closes.slice(-20));
    const dropPct = ((max20 - price) / max20) * 100;
    const rsi     = calcRSI(closes, 14);
    const ema200  = calcEMA(closes, 200);
    const ema50   = calcEMA(closes, 50);
    const trend   = price > ema200;
    const vol20   = volumes.slice(-20).reduce((a,b)=>a+b,0)/20;
    const volNow  = volumes[volumes.length-1]||0;
    const volRel  = vol20>0 ? volNow/vol20 : 1;
    const rebProb = calcReboundProb(closes);
    res.json({
      ok:true, ticker, price, prevClose, changeDay,
      high52w: meta.fiftyTwoWeekHigh, low52w: meta.fiftyTwoWeekLow,
      mktCap: meta.marketCap,
      pe: meta.trailingPE||null, fwdPe: meta.forwardPE||null,
      eps: meta.epsTrailingTwelveMonths||null,
      divYield: meta.dividendYield ? meta.dividendYield*100 : null,
      beta: meta.beta||null, dropFromHigh: dropPct,
      rsi14: rsi, ema200, ema50, trend,
      volHigh: volNow > vol20*1.5,
      volRelative: parseFloat(volRel.toFixed(2)),
      reboundProb5: rebProb.p5, reboundProb10: rebProb.p10,
      reboundProb15: rebProb.p15, reboundProb20: rebProb.p20,
      reboundProb30: rebProb.p30, reboundProb40: rebProb.p40,
      historicalCases: rebProb.count,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CHART DATA — OHLCV multi-timeframe ───────────────────
// Mapeo: timeframe -> parametros Yahoo Finance
const TF_MAP = {
  '1d':  { interval:'1d',  range:'1y'  },
  '1wk': { interval:'1wk', range:'5y'  },
  '1mo': { interval:'1mo', range:'10y' },
  '1h':  { interval:'1h',  range:'60d' },
  '4h':  { interval:'1h',  range:'60d' }, // Yahoo no tiene 4h, usamos 1h
  '15m': { interval:'15m', range:'5d'  },
  '5m':  { interval:'5m',  range:'1d'  },
};

app.get('/api/chart/:ticker', authMiddleware, async (req, res) => {
  const { ticker } = req.params;
  const tf  = req.query.tf  || '1d';
  const ema = parseInt(req.query.ema) || 200;
  const cfg = TF_MAP[tf] || TF_MAP['1d'];

  try {
    const url  = `https://query1.finance.yahoo.com/v8/finance/chart/${ticker}?interval=${cfg.interval}&range=${cfg.range}`;
    const resp = await fetch(url, { headers:{'User-Agent':'Mozilla/5.0'}, timeout:12000 });
    const json = await resp.json();
    if (!json.chart?.result?.length) return res.status(404).json({ error:'Sin datos' });

    const r       = json.chart.result[0];
    const ts      = r.timestamp;
    const q       = r.indicators.quote[0];
    const closes  = q.close;
    const opens   = q.open;
    const highs   = q.high;
    const lows    = q.low;
    const volumes = q.volume;

    // Calcular EMA configurable
    function calcEMAArr(data, period) {
      const result = new Array(data.length).fill(null);
      let sum = 0, count = 0;
      for (let i = 0; i < data.length; i++) {
        if (data[i] == null) { result[i] = null; continue; }
        if (count < period) {
          sum += data[i]; count++;
          if (count === period) result[i] = sum / period;
          else result[i] = null;
        } else {
          const k = 2 / (period + 1);
          result[i] = data[i] * k + result[i-1] * (1 - k);
        }
      }
      return result;
    }

    const emaArr = calcEMAArr(closes, ema);

    // Detectar posicion del precio respecto a la EMA
    const lastClose = closes[closes.length-1];
    const lastEMA   = emaArr[emaArr.length-1];
    const emaTrend  = lastClose > lastEMA ? 'above' : 'below';
    const emaDiff   = lastEMA ? ((lastClose - lastEMA) / lastEMA * 100) : 0;

    // Detectar cruce reciente (ultimas 5 velas)
    let recentCross = null;
    for (let i = closes.length-1; i >= Math.max(0, closes.length-5); i--) {
      if (!closes[i]||!emaArr[i]||!closes[i-1]||!emaArr[i-1]) continue;
      if (closes[i] > emaArr[i] && closes[i-1] <= emaArr[i-1]) { recentCross = 'golden'; break; }
      if (closes[i] < emaArr[i] && closes[i-1] >= emaArr[i-1]) { recentCross = 'death';  break; }
    }

    // Soporte/resistencia en la EMA
    const distToEMA = lastEMA ? Math.abs(lastClose - lastEMA) / lastClose * 100 : 0;
    const nearEMA   = distToEMA < 1.5;

    // Señal del timeframe
    let tfSignal = 'neutral';
    if (emaTrend === 'above' && recentCross === 'golden') tfSignal = 'strong_bull';
    else if (emaTrend === 'above') tfSignal = 'bull';
    else if (emaTrend === 'below' && recentCross === 'death') tfSignal = 'strong_bear';
    else if (emaTrend === 'below') tfSignal = 'bear';

    // OHLCV limpio (filtrar nulls)
    const candles = [];
    for (let i = 0; i < ts.length; i++) {
      if (closes[i] == null) continue;
      candles.push({
        t: ts[i] * 1000,
        o: opens[i],
        h: highs[i],
        l: lows[i],
        c: closes[i],
        v: volumes[i] || 0,
        ema: emaArr[i],
      });
    }

    res.json({
      ok: true, ticker, tf, ema,
      candles,
      lastClose, lastEMA,
      emaTrend, emaDiff: parseFloat(emaDiff.toFixed(2)),
      recentCross, nearEMA, tfSignal,
      distToEMA: parseFloat(distToEMA.toFixed(2)),
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── SEÑAL EN MULTIPLES TIMEFRAMES ────────────────────────
app.get('/api/signal/:ticker', authMiddleware, async (req, res) => {
  const { ticker } = req.params;
  const ema = parseInt(req.query.ema) || 200;
  const timeframes = ['1d','1wk','1mo'];
  const results = {};

  await Promise.all(timeframes.map(async tf => {
    try {
      const cfg = TF_MAP[tf];
      const url = `https://query1.finance.yahoo.com/v8/finance/chart/${ticker}?interval=${cfg.interval}&range=${cfg.range}`;
      const resp = await fetch(url, { headers:{'User-Agent':'Mozilla/5.0'}, timeout:10000 });
      const json = await resp.json();
      if (!json.chart?.result?.length) return;
      const closes = json.chart.result[0].indicators.quote[0].close.filter(v => v != null);
      if (closes.length < ema) return;
      const k = 2/(ema+1);
      let emaVal = closes.slice(0,ema).reduce((a,b)=>a+b,0)/ema;
      for (let i = ema; i < closes.length; i++) emaVal = closes[i]*k + emaVal*(1-k);
      const last = closes[closes.length-1];
      const prev = closes[closes.length-2];
      const prevEMA = emaVal * (1 - k) + closes[closes.length-1] * k; // aproximacion
      const trend = last > emaVal ? 'above' : 'below';
      const diff  = ((last - emaVal) / emaVal * 100).toFixed(2);
      let cross = null;
      if (last > emaVal && prev <= emaVal) cross = 'golden';
      if (last < emaVal && prev >= emaVal) cross = 'death';
      results[tf] = { trend, diff: parseFloat(diff), cross, ema: parseFloat(emaVal.toFixed(4)), price: last };
    } catch(e) { results[tf] = { error: e.message }; }
  }));

  res.json({ ok: true, ticker, ema, signals: results });
});

// ── DRIVERS IA — PRO ONLY ─────────────────────────────────
app.post('/api/drivers', authMiddleware, proMiddleware, async (req, res) => {
  const { ticker, stockData } = req.body;
  try {
    const prompt = `Eres analista financiero experto. Para ${ticker} (precio: $${stockData.price?.toFixed(2)}, caida: ${stockData.dropFromHigh?.toFixed(1)}%) responde SOLO JSON puro:
{"revenue":"400B","margin":25.0,"debtEquity":0.8,"roe":35.0,"drivers":[{"type":"bull","icon":"📈","text":"Driver alcista ESPECÍFICO de ${ticker}","strength":"Alto"},{"type":"bull","icon":"💰","text":"Segundo driver alcista de ${ticker}","strength":"Medio"},{"type":"bear","icon":"⚠️","text":"Riesgo bajista principal de ${ticker}","strength":"Alto"},{"type":"bear","icon":"📉","text":"Segundo riesgo de ${ticker}","strength":"Medio"},{"type":"neutral","icon":"⚖️","text":"Catalizador a vigilar en ${ticker}","strength":"Medio"}],"outlook":"COMPRA","outlookReason":"Razón específica en 1 frase para ${ticker}"}`;
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{'Content-Type':'application/json','x-api-key': process.env.ANTHROPIC_API_KEY||''},
      body: JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:800, messages:[{role:'user',content:prompt}] }),
      timeout: 30000
    });
    const data = await resp.json();
    const text = data.content[0].text;
    const parsed = JSON.parse(text.replace(/```json|```/g,'').trim());
    res.json({ ok:true, ...parsed });
  } catch(e) {
    res.json({ ok:false, error:e.message, drivers:[], outlook:'—', outlookReason:'No disponible' });
  }
});

// ── STRIPE PAGOS ──────────────────────────────────────────
app.post('/api/stripe/checkout', authMiddleware, async (req, res) => {
  if (!STRIPE_KEY) return res.status(500).json({ error: 'Stripe no configurado' });
  try {
    const stripe = require('stripe')(STRIPE_KEY);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, name: user.name });
      customerId = customer.id;
      db.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').run(customerId, user.id);
    }
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      success_url: `${req.headers.origin}/success.html`,
      cancel_url:  `${req.headers.origin}/`,
    });
    res.json({ ok:true, url: session.url });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Stripe webhook
app.post('/api/stripe/webhook', express.raw({type:'application/json'}), (req, res) => {
  if (!STRIPE_KEY) return res.json({received:true});
  try {
    const stripe = require('stripe')(STRIPE_KEY);
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET||'');
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const user = db.prepare('SELECT * FROM users WHERE stripe_customer_id = ?').get(session.customer);
      if (user) {
        db.prepare('UPDATE users SET plan = "pro", stripe_subscription_id = ? WHERE id = ?').run(session.subscription, user.id);
        sendProEmail(user.email, user.name);
      }
    }
    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      db.prepare('UPDATE users SET plan = "free" WHERE stripe_subscription_id = ?').run(sub.id);
    }
    res.json({received:true});
  } catch(e) {
    res.status(400).json({error:e.message});
  }
});

// ── ALERTAS ───────────────────────────────────────────────
// ── WHATSAPP CONFIG ───────────────────────────────────────
app.post('/api/alerts/whatsapp', authMiddleware, (req, res) => {
  const { phone, apikey, enabled } = req.body;
  db.prepare('UPDATE users SET whatsapp_phone = ?, whatsapp_apikey = ?, whatsapp_enabled = ? WHERE id = ?')
    .run(phone||null, apikey||null, enabled?1:0, req.user.id);
  res.json({ ok: true });
});

// Test WhatsApp
app.post('/api/alerts/whatsapp/test', authMiddleware, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user.whatsapp_phone || !user.whatsapp_apikey) {
    return res.status(400).json({ error: 'Configura tu número y API key primero' });
  }
  const sent = await sendWhatsApp(user.whatsapp_phone, user.whatsapp_apikey,
    '✅ TradeSmart AI: Prueba de alerta exitosa. Tus alertas de acciones están activas.');
  res.json({ ok: sent, message: sent ? 'Mensaje enviado' : 'Error al enviar' });
});

app.post('/api/alerts/settings', authMiddleware, (req, res) => {
  const { enabled, dropAlert } = req.body;
  db.prepare('UPDATE users SET alerts_enabled = ?, drop_alert = ? WHERE id = ?').run(enabled?1:0, dropAlert, req.user.id);
  res.json({ ok:true });
});

// Job que corre cada hora y manda alertas
async function checkAlerts() {
  const users = db.prepare('SELECT * FROM users WHERE alerts_enabled = 1').all();
  for (const user of users) {
    const watchlist = JSON.parse(user.watchlist || '[]');
    for (const ticker of watchlist.slice(0,5)) {
      try {
        const url = `https://query1.finance.yahoo.com/v8/finance/chart/${ticker}?interval=1d&range=20d`;
        const r = await fetch(url, { headers:{'User-Agent':'Mozilla/5.0'}, timeout:8000 });
        const json = await r.json();
        if (!json.chart?.result?.length) continue;
        const closes = json.chart.result[0].indicators.quote[0].close.filter(v=>v!=null);
        const price  = closes[closes.length-1];
        const max20  = Math.max(...closes.slice(-20));
        const drop   = ((max20-price)/max20)*100;
        if (drop >= (user.drop_alert||5)) {
          // Email alert
          sendAlertEmail(user.email, user.name, ticker, price, drop);
          // WhatsApp alert
          if (user.whatsapp_enabled && user.whatsapp_phone && user.whatsapp_apikey) {
            const msg = `🚨 TradeSmart AI\n${ticker} cayó ${drop.toFixed(1)}% desde máximo\nPrecio: $${price.toFixed(2)}\nPosible oportunidad de compra\n\nhttps://spy-dovi.onrender.com`;
            sendWhatsApp(user.whatsapp_phone, user.whatsapp_apikey, msg);
          }
        }
      } catch(e) { /* skip */ }
    }
  }
}

// Correr alertas cada hora
setInterval(checkAlerts, 60*60*1000);

// ── EMAIL ─────────────────────────────────────────────────
function getMailer() {
  if (!EMAIL_USER) return null;
  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
  });
}

function sendWelcomeEmail(email, name) {
  const mailer = getMailer();
  if (!mailer) return;
  mailer.sendMail({
    from: `TradeSmart AI <${EMAIL_USER}>`,
    to: email,
    subject: '¡Bienvenido a TradeSmart AI! 🚀',
    html: `<h2>Hola ${name}!</h2><p>Tu cuenta está lista. Analiza Las 7 Magnificas y cualquier acción con IA.</p><p>Upgrade a <strong>Pro por $9.99/mes</strong> para acceder a todos los drivers de IA y alertas ilimitadas.</p><br><a href="https://spy-dovi.onrender.com" style="background:#ffd700;padding:12px 24px;border-radius:6px;text-decoration:none;color:#000;font-weight:bold">Ir a TradeSmart AI</a>`
  }).catch(()=>{});
}

function sendProEmail(email, name) {
  const mailer = getMailer();
  if (!mailer) return;
  mailer.sendMail({
    from: `TradeSmart AI <${EMAIL_USER}>`,
    to: email,
    subject: '¡Ya eres Pro! ⭐ TradeSmart AI',
    html: `<h2>¡Bienvenido al Plan Pro, ${name}!</h2><p>Ahora tienes acceso a:</p><ul><li>✅ Drivers IA ilimitados</li><li>✅ Hasta 50 acciones en watchlist</li><li>✅ Alertas de caida automáticas</li><li>✅ Análisis completo de fundamentales</li></ul><br><a href="https://spy-dovi.onrender.com" style="background:#ffd700;padding:12px 24px;border-radius:6px;text-decoration:none;color:#000;font-weight:bold">Ir a TradeSmart AI</a>`
  }).catch(()=>{});
}

// ── WHATSAPP VIA CALLMEBOT ────────────────────────────────
async function sendWhatsApp(phone, apikey, message) {
  try {
    const encoded = encodeURIComponent(message);
    const url = `https://api.callmebot.com/whatsapp.php?phone=${phone}&text=${encoded}&apikey=${apikey}`;
    const resp = await fetch(url, { timeout: 10000 });
    const text = await resp.text();
    console.log('WhatsApp response:', text);
    return resp.ok;
  } catch(e) {
    console.error('WhatsApp error:', e.message);
    return false;
  }
}

function sendAlertEmail(email, name, ticker, price, drop) {
  const mailer = getMailer();
  if (!mailer) return;
  mailer.sendMail({
    from: `TradeSmart AI <${EMAIL_USER}>`,
    to: email,
    subject: `🚨 ALERTA: ${ticker} cayó ${drop.toFixed(1)}% — Posible oportunidad`,
    html: `<h2>¡Alerta de caida! ${ticker}</h2><p>Hola ${name},</p><p><strong>${ticker}</strong> ha caído <strong>${drop.toFixed(1)}%</strong> desde su máximo reciente.</p><p>Precio actual: <strong>$${price.toFixed(2)}</strong></p><p>Esta puede ser una oportunidad de compra. Revisa el análisis completo en TradeSmart AI.</p><br><a href="https://spy-dovi.onrender.com" style="background:#00e676;padding:12px 24px;border-radius:6px;text-decoration:none;color:#000;font-weight:bold">Ver Análisis Completo</a>`
  }).catch(()=>{});
}

// ── HELPERS ───────────────────────────────────────────────
function calcRSI(data, period=14) {
  if(data.length<period+1)return 50;
  let g=0,l=0;
  for(let i=data.length-period;i<data.length;i++){const d=data[i]-data[i-1];if(d>0)g+=d;else l-=d;}
  return parseFloat((100-(100/(1+(g/(l||0.001))))).toFixed(1));
}
function calcEMA(data,period) {
  if(data.length<period)return data[data.length-1];
  const k=2/(period+1);
  let ema=data.slice(0,period).reduce((a,b)=>a+b,0)/period;
  for(let i=period;i<data.length;i++)ema=data[i]*k+ema*(1-k);
  return parseFloat(ema.toFixed(4));
}
function calcReboundProb(closes) {
  if(closes.length<60)return{p5:65,p10:55,p15:45,p20:40,p30:32,p40:25,count:0};
  let d5=0,r5=0,d10=0,r10=0,d15=0,r15=0,d20=0,r20=0,d30=0,r30=0,d40=0,r40=0;
  for(let i=20;i<closes.length-15;i++){
    const max=Math.max(...closes.slice(i-20,i));
    const drop=(max-closes[i])/max*100;
    // Mirar rebote a 15 velas adelante para caidas mayores
    const fut=Math.max(...closes.slice(i,i+15));
    const reb=(fut-closes[i])/closes[i]*100;
    if(drop>=5) {d5++;  if(reb>=5)r5++;}
    if(drop>=10){d10++; if(reb>=5)r10++;}
    if(drop>=15){d15++; if(reb>=5)r15++;}
    if(drop>=20){d20++; if(reb>=5)r20++;}
    if(drop>=30){d30++; if(reb>=5)r30++;}
    if(drop>=40){d40++; if(reb>=5)r40++;}
  }
  return{
    p5:  d5>0  ? Math.round(r5/d5*100)   : 65,
    p10: d10>0 ? Math.round(r10/d10*100) : 55,
    p15: d15>0 ? Math.round(r15/d15*100) : 45,
    p20: d20>0 ? Math.round(r20/d20*100) : 38,
    p30: d30>0 ? Math.round(r30/d30*100) : 30,
    p40: d40>0 ? Math.round(r40/d40*100) : 22,
    count: d5
  };
}

app.listen(PORT, () => {
  console.log(`✅ TradeSmart AI corriendo en http://localhost:${PORT}`);
  console.log(`   JEFER85 | SaaS Mode | Pro: $9.99/mes`);
});
