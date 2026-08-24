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
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, 'csp-reports.log');

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

app.use(express.json({ type: ['application/json', 'application/csp-report'] }));

function getHostname(uri) {
  try {
    return new URL(uri).hostname;
  } catch {
    return 'desconhecido';
  }
}

async function sendDigestEmail(hostname, reports) {
  if (!transporter) return;

  const rows = reports
    .map(
      (r) =>
        `<tr>
          <td>${r.timestamp}</td>
          <td>${r.blockedUri}</td>
          <td>${r.violatedDirective}</td>
          <td>${r.documentUri}</td>
        </tr>`
    )
    .join('');

  const html = `
    <p>${reports.length} violação(ões) de CSP detetada(s) em <b>${hostname}</b>
    nos últimos minutos.</p>
    <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-family:sans-serif;font-size:13px;">
      <tr style="background:#f0f0f0;">
        <th>Quando</th><th>Bloqueado</th><th>Diretiva</th><th>Página</th>
      </tr>
      ${rows}
    </table>
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
    pendingByDomain.set(hostname, { reports: [], timer: null });
    sendDigestEmail(hostname, reports);
  }, DEBOUNCE_MS);
}

app.post('/report', (req, res) => {
  const report = req.body['csp-report'] || req.body;

  const entry = {
    timestamp: new Date().toISOString(),
    blockedUri: report['blocked-uri'] || report.blockedURI,
    violatedDirective: report['violated-directive'] || report.violatedDirective,
    documentUri: report['document-uri'] || report.documentURI,
    disposition: report.disposition,
  };

  fs.appendFile(LOG_FILE, JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error('Erro a gravar log:', err.message);
  });
  console.log('CSP violation:', entry);

  const hostname = getHostname(entry.documentUri);
  if (!pendingByDomain.has(hostname)) {
    pendingByDomain.set(hostname, { reports: [], timer: null });
  }
  pendingByDomain.get(hostname).reports.push(entry);
  scheduleDigest(hostname);

  res.status(204).end();
});

// Consulta rápida dos últimos relatórios, opcionalmente filtrados por site:
// GET /reports            -> últimos 50 de todos os sites
// GET /reports?site=lmrcirurgiaplastica.pt -> só desse site
app.get('/reports', (req, res) => {
  if (!fs.existsSync(LOG_FILE)) return res.json([]);
  let lines = fs.readFileSync(LOG_FILE, 'utf-8').trim().split('\n').filter(Boolean);
  let entries = lines.map((l) => JSON.parse(l));

  if (req.query.site) {
    entries = entries.filter((e) => getHostname(e.documentUri).includes(req.query.site));
  }

  res.json(entries.slice(-50).reverse());
});

app.listen(PORT, () => {
  console.log(`CSP report collector a correr na porta ${PORT}`);
});
