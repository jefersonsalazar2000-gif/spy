const express = require('express');
const fetch   = require('node-fetch');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Servir index.html desde la raiz (no desde /public)
app.use(express.static(path.join(__dirname)));

// ── YAHOO FINANCE ─────────────────────────────────────────
app.get('/api/stock/:ticker', async (req, res) => {
  const { ticker } = req.params;
  try {
    const url  = `https://query1.finance.yahoo.com/v8/finance/chart/${ticker}?interval=1d&range=2y`;
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      timeout: 10000
    });
    const json = await resp.json();

    if (!json.chart?.result?.length) {
      return res.status(404).json({ error: 'Ticker no encontrado: ' + ticker });
    }

    const r       = json.chart.result[0];
    const meta    = r.meta;
    const q       = r.indicators.quote[0];
    const closes  = q.close.filter(v => v != null);
    const volumes = q.volume.filter(v => v != null);

    const price     = meta.regularMarketPrice || closes[closes.length - 1];
    const prevClose = meta.previousClose || meta.chartPreviousClose;
    const high52w   = meta.fiftyTwoWeekHigh;
    const low52w    = meta.fiftyTwoWeekLow;
    const mktCap    = meta.marketCap;
    const changeDay = ((price - prevClose) / prevClose) * 100;

    const max20    = Math.max(...closes.slice(-20));
    const dropPct  = ((max20 - price) / max20) * 100;
    const rsi      = calcRSI(closes, 14);
    const ema200   = calcEMA(closes, 200);
    const ema50    = calcEMA(closes, 50);
    const trend    = price > ema200;
    const vol20    = volumes.slice(-20).reduce((a, b) => a + b, 0) / 20;
    const volNow   = volumes[volumes.length - 1] || 0;
    const volHigh  = volNow > vol20 * 1.5;
    const volRel   = vol20 > 0 ? volNow / vol20 : 1;
    const rebProb  = calcReboundProb(closes, dropPct);

    res.json({
      ok: true, ticker,
      price, prevClose, changeDay, high52w, low52w, mktCap,
      pe:       meta.trailingPE   || null,
      fwdPe:    meta.forwardPE    || null,
      eps:      meta.epsTrailingTwelveMonths || null,
      divYield: meta.dividendYield ? meta.dividendYield * 100 : null,
      beta:     meta.beta         || null,
      dropFromHigh: dropPct,
      rsi14:    rsi,
      ema200, ema50, trend,
      volHigh, volRelative: parseFloat(volRel.toFixed(2)),
      reboundProb5:  rebProb.p5,
      reboundProb10: rebProb.p10,
      reboundProb15: rebProb.p15,
      historicalCases: rebProb.count,
    });

  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── CLAUDE API — DRIVERS IA ───────────────────────────────
app.post('/api/drivers', async (req, res) => {
  const { ticker, stockData } = req.body;
  try {
    const prompt = `Eres analista financiero experto con datos actualizados a junio 2025.
Para la acción ${ticker} (precio actual: $${stockData.price?.toFixed(2)}, caida desde max: ${stockData.dropFromHigh?.toFixed(1)}%)
responde SOLO con JSON puro sin markdown ni texto extra:
{
  "revenue": "400B",
  "margin": 25.0,
  "debtEquity": 0.8,
  "roe": 35.0,
  "drivers": [
    {"type": "bull", "icon": "📈", "text": "Driver alcista MUY ESPECÍFICO y actual de ${ticker}", "strength": "Alto"},
    {"type": "bull", "icon": "💰", "text": "Segundo driver alcista específico de ${ticker}", "strength": "Medio"},
    {"type": "bear", "icon": "⚠️", "text": "Riesgo bajista principal y actual de ${ticker}", "strength": "Alto"},
    {"type": "bear", "icon": "📉", "text": "Segundo riesgo específico de ${ticker}", "strength": "Medio"},
    {"type": "neutral", "icon": "⚖️", "text": "Catalizador clave a vigilar en ${ticker}", "strength": "Medio"}
  ],
  "outlook": "COMPRA",
  "outlookReason": "Razón específica en 1 frase para ${ticker} con precio actual"
}
Drivers MUY ESPECÍFICOS para ${ticker}. No genéricos.`;

    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 800,
        messages: [{ role: 'user', content: prompt }]
      }),
      timeout: 30000
    });

    const data  = await resp.json();
    const text  = data.content[0].text;
    const clean = text.replace(/```json|```/g, '').trim();
    const parsed= JSON.parse(clean);
    res.json({ ok: true, ...parsed });

  } catch (e) {
    res.json({ ok: false, error: e.message, drivers: [], outlook: '—', outlookReason: 'No disponible' });
  }
});

// ── HELPERS ───────────────────────────────────────────────
function calcRSI(data, period = 14) {
  if (data.length < period + 1) return 50;
  let gains = 0, losses = 0;
  for (let i = data.length - period; i < data.length; i++) {
    const d = data[i] - data[i - 1];
    if (d > 0) gains += d; else losses -= d;
  }
  const rs = gains / (losses || 0.001);
  return parseFloat((100 - (100 / (1 + rs))).toFixed(1));
}

function calcEMA(data, period) {
  if (data.length < period) return data[data.length - 1];
  const k = 2 / (period + 1);
  let ema = data.slice(0, period).reduce((a, b) => a + b, 0) / period;
  for (let i = period; i < data.length; i++) ema = data[i] * k + ema * (1 - k);
  return parseFloat(ema.toFixed(4));
}

function calcReboundProb(closes, currentDrop) {
  if (closes.length < 60) return { p5: 65, p10: 55, p15: 45, count: 0 };
  let d5=0,r5=0, d10=0,r10=0, d15=0,r15=0;
  for (let i = 20; i < closes.length - 10; i++) {
    const localMax = Math.max(...closes.slice(i - 20, i));
    const drop     = (localMax - closes[i]) / localMax * 100;
    const future   = Math.max(...closes.slice(i, i + 10));
    const rebound  = (future - closes[i]) / closes[i] * 100;
    if (drop >= 5)  { d5++;  if (rebound >= 5) r5++;  }
    if (drop >= 10) { d10++; if (rebound >= 5) r10++; }
    if (drop >= 15) { d15++; if (rebound >= 5) r15++; }
  }
  return {
    p5:  d5  > 0 ? Math.round(r5  / d5  * 100) : 65,
    p10: d10 > 0 ? Math.round(r10 / d10 * 100) : 55,
    p15: d15 > 0 ? Math.round(r15 / d15 * 100) : 45,
    count: d5
  };
}

app.listen(PORT, () => {
  console.log(`✅ Stock Analyzer Pro corriendo en http://localhost:${PORT}`);
  console.log(`   JEFER85 | Las 7 Magnificas + SPY + Ford + Cualquier accion`);
});
