// CSP Report Collector — v2 (notificação por EMAIL via SMTP)
// Serve para os 10 sites em simultâneo: o document-uri de cada
// relatório já diz de que site veio, por isso um único endpoint chega.
//
// Setup:
//   1. npm install
//   2. Define as variáveis de ambiente no Coolify (ver lista abaixo)
//   3. Aponta a CSP de cada site para: report-uri https://csp.picturethis.pt/report;

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
// Pasta persistente: no Coolify é um volume montado em /app/data.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const LOG_FILE = path.join(DATA_DIR, 'csp-reports.log');
const MAX_LOG_BYTES = 20 * 1024 * 1024; // acima disto, roda para .1

// Acesso a GET /reports (Basic Auth). Sem estas variáveis, o acesso é recusado.
const REPORTS_USER = process.env.REPORTS_USER;
const REPORTS_PASSWORD = process.env.REPORTS_PASSWORD;

// Limites de POST /report, para evitar abuso e emails em massa.
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX_PER_IP = 60;
const RATE_MAX_GLOBAL = 600;
const MAX_ROWS_PER_EMAIL = 50;
const MAX_PENDING_SITES = 50;
const MAX_FIELD_LENGTH = 500;

// --- Configuração SMTP (variáveis de ambiente no Coolify) ---
const SMTP_HOST = process.env.SMTP_HOST;           // ex: smtp.zoho.eu
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;           // ex: notificacoes@picturethis.pt
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const ALERT_TO = process.env.ALERT_TO || 'info@picturethis.pt';

// Evita mandar um email por CADA violação (se um script partido disparar
// 50 vezes por segundo, não queres 50 emails) — agrupa por 5 minutos.
const DEBOUNCE_MS = 5 * 60 * 1000;
const pendingByDomain = new Map(); // hostname -> { reports: [], timer }

let transporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
} else {
  console.warn('SMTP não configurado — emails não serão enviados, só gravados no log.');
}

app.use(express.json({ limit: '32kb', type: ['application/json', 'application/csp-report', 'application/reports+json'] }));

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function requireAuth(req, res, next) {
  if (!REPORTS_USER || !REPORTS_PASSWORD) {
    return res.status(503).send('Acesso a relatórios não configurado.');
  }
  const [scheme, encoded] = (req.headers.authorization || '').split(' ');
  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
    const sep = decoded.indexOf(':');
    if (sep !== -1) {
      const userOk = safeEqual(decoded.slice(0, sep), REPORTS_USER);
      const passOk = safeEqual(decoded.slice(sep + 1), REPORTS_PASSWORD);
      if (userOk && passOk) return next();
    }
  }
  res.set('WWW-Authenticate', 'Basic realm="CSP reports", charset="UTF-8"');
  return res.status(401).send('Autenticação necessária.');
}

// Limite simples em memória, por IP e global, numa janela de um minuto.
const rate = { start: 0, total: 0, perIp: new Map() };

function rateLimited(ip) {
  const now = Date.now();
  if (now - rate.start >= RATE_WINDOW_MS) {
    rate.start = now;
    rate.total = 0;
    rate.perIp.clear();
  }
  rate.total += 1;
  const count = (rate.perIp.get(ip) || 0) + 1;
  rate.perIp.set(ip, count);
  return count > RATE_MAX_PER_IP || rate.total > RATE_MAX_GLOBAL;
}

function clientIp(req) {
  // As portas 80/443 da VPS estão fechadas: o tráfego só chega pelo Cloudflare Tunnel.
  return req.headers['cf-connecting-ip'] || req.ip;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function clip(value) {
  return typeof value === 'string' ? value.slice(0, MAX_FIELD_LENGTH) : value;
}

function rotateLogIfNeeded() {
  try {
    if (fs.statSync(LOG_FILE).size > MAX_LOG_BYTES) {
      fs.renameSync(LOG_FILE, `${LOG_FILE}.1`);
    }
  } catch (err) {
    if (err.code !== 'ENOENT') console.error('Erro a rodar log:', err.message);
  }
}

function getHostname(uri) {
  try {
    const url = new URL(uri);
    return /^https?:$/.test(url.protocol) ? url.hostname : 'desconhecido';
  } catch {
    return 'desconhecido';
  }
}

async function sendDigestEmail(hostname, reports) {
  if (!transporter) return;

  const rows = reports
    .slice(0, MAX_ROWS_PER_EMAIL)
    .map(
      (r) =>
        `<tr>
          <td>${escapeHtml(r.timestamp)}</td>
          <td>${escapeHtml(r.blockedUri)}</td>
          <td>${escapeHtml(r.violatedDirective)}</td>
          <td>${escapeHtml(r.documentUri)}</td>
        </tr>`
    )
    .join('');

  const html = `
    <p>${reports.length} violação(ões) de CSP detetada(s) em <b>${escapeHtml(hostname)}</b>
    nos últimos minutos.</p>
    <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-family:sans-serif;font-size:13px;">
      <tr style="background:#f0f0f0;">
        <th>Quando</th><th>Bloqueado</th><th>Diretiva</th><th>Página</th>
      </tr>
      ${rows}
    </table>
    ${reports.length > MAX_ROWS_PER_EMAIL ? `<p>Mostradas ${MAX_ROWS_PER_EMAIL} de ${reports.length}.</p>` : ''}
  `;

  try {
    await transporter.sendMail({
      from: SMTP_FROM,
      to: ALERT_TO,
      subject: `⚠️ CSP: ${reports.length} violação(ões) em ${hostname}`,
      html,
    });
  } catch (err) {
    console.error('Falha ao enviar email:', err.message);
  }
}

function scheduleDigest(hostname) {
  const entry = pendingByDomain.get(hostname);
  if (entry.timer) return; // já agendado, espera o debounce

  entry.timer = setTimeout(() => {
    const reports = entry.reports;
    pendingByDomain.delete(hostname);
    sendDigestEmail(hostname, reports);
  }, DEBOUNCE_MS);
}

app.post('/report', (req, res) => {
  if (rateLimited(clientIp(req))) return res.status(429).end();

  const report = req.body?.['csp-report'] || req.body;
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    return res.status(400).end();
  }

  const entry = {
    timestamp: new Date().toISOString(),
    blockedUri: clip(report['blocked-uri'] || report.blockedURI),
    violatedDirective: clip(report['violated-directive'] || report.violatedDirective),
    documentUri: clip(report['document-uri'] || report.documentURI),
    disposition: clip(report.disposition),
  };

  // Sem uma página http(s) válida não é um relatório útil: ignora sem gravar.
  const hostname = getHostname(entry.documentUri);
  if (hostname === 'desconhecido') return res.status(204).end();

  rotateLogIfNeeded();
  fs.appendFile(LOG_FILE, JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error('Erro a gravar log:', err.message);
  });
  console.log('CSP violation:', entry);

  if (pendingByDomain.has(hostname) || pendingByDomain.size < MAX_PENDING_SITES) {
    if (!pendingByDomain.has(hostname)) {
      pendingByDomain.set(hostname, { reports: [], timer: null });
    }
    pendingByDomain.get(hostname).reports.push(entry);
    scheduleDigest(hostname);
  }

  res.status(204).end();
});

// Consulta rápida dos últimos relatórios, opcionalmente filtrados por site:
// GET /reports            -> últimos 50 de todos os sites
// GET /reports?site=lmrcirurgiaplastica.pt -> só desse site
app.get('/reports', requireAuth, (req, res) => {
  if (!fs.existsSync(LOG_FILE)) return res.json([]);
  let lines = fs.readFileSync(LOG_FILE, 'utf-8').trim().split('\n').filter(Boolean);
  let entries = lines.flatMap((l) => {
    try {
      return [JSON.parse(l)];
    } catch {
      return [];
    }
  });

  if (req.query.site) {
    entries = entries.filter((e) => getHostname(e.documentUri).includes(req.query.site));
  }

  res.json(entries.slice(-50).reverse());
});

// JSON inválido ou demasiado grande não deve gerar página de erro com detalhes.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  return res.status(err.status || 500).end();
});

app.listen(PORT, () => {
  console.log(`CSP report collector a correr na porta ${PORT}`);
});
