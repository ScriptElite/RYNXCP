'use strict';

/* RYNXCP panel client. No external dependencies, CSP friendly. */

const S = {
  user: null,
  csrf: null,
  current: 'overview',
  navToken: 0,
  system: null,
  mode: null,
  phpVersions: null,
  impersonatedBy: null,
  resetToken: null,
  twoFactorChallenge: null,
  data: { accounts: [], websites: [], apps: [], pools: [], certs: [], users: [], packages: [], accountPackages: [], mailDomains: [], mailAccounts: [], agentFindings: [] },
  files: { domain: '', path: '', entries: [] },
};

let agentPollTimer = null;
const AGENT_POLL_MS = 30000;

const RUNTIMES = {
  static: { label: 'Sitio estático', short: 'Static', versions: [], commands: [] },
  php: { label: 'PHP (FPM)', short: 'PHP', versions: ['8.5', '8.4', '8.3', '8.2', '8.1'], commands: [] },
  node: { label: 'Node.js (systemd)', short: 'Node', versions: ['24', '22', '20', '18'], commands: ['node'], entry: 'server.js', exampleArgs: 'server.js' },
  python: { label: 'Python (WSGI/ASGI)', short: 'Python', versions: ['3.13', '3.12', '3.11', '3.10'], commands: ['gunicorn', 'uvicorn', 'python3'], entry: 'app.py', exampleArgs: 'app:app --bind=127.0.0.1:4100' },
  ruby: { label: 'Ruby', short: 'Ruby', versions: ['3.4', '3.3', '3.2'], commands: ['puma', 'bundle', 'rackup', 'ruby'], entry: 'config.ru', exampleArgs: 'config.ru' },
  java: { label: 'Java (JAR)', short: 'Java', versions: ['21', '17', '11'], commands: ['java'], entry: 'app.jar', exampleArgs: '-jar app.jar' },
  dotnet: { label: '.NET', short: '.NET', versions: ['9', '8'], commands: ['dotnet'], entry: 'App.dll', exampleArgs: 'App.dll' },
  go: { label: 'Go (binario compilado)', short: 'Go', versions: [], commands: [], entry: 'server', exampleArgs: '' },
};

const MANAGED = ['node', 'python', 'ruby', 'java', 'dotnet', 'go'];

const WEB_BACKEND_OPTIONS = [
  { value: 'static', label: 'Estático' },
  { value: 'php', label: 'PHP (FPM)' },
  { value: 'node', label: 'Node.js (systemd)' },
  { value: 'python', label: 'Python (WSGI/ASGI)' },
  { value: 'ruby', label: 'Ruby' },
  { value: 'java', label: 'Java (JAR)' },
  { value: 'dotnet', label: '.NET' },
  { value: 'go', label: 'Go (binario compilado)' },
];

const NAV_ITEMS = [
  { id: 'overview', label: 'Resumen', group: 'Operación' },
  { id: 'accounts', label: 'Cuentas', group: 'Operación' },
  { id: 'websites', label: 'Sitios web', group: 'Operación' },
  { id: 'files', label: 'Archivos', group: 'Operación' },
  { id: 'apps', label: 'Aplicaciones', group: 'Operación' },
  { id: 'installer', label: 'Instalador', group: 'Operación' },
  { id: 'php', label: 'PHP-FPM', group: 'Operación' },
  { id: 'databases', label: 'Bases de datos', group: 'Operación' },
  { id: 'ftp', label: 'FTP', group: 'Operación' },
  { id: 'dns', label: 'DNS', group: 'Operación' },
  { id: 'mail', label: 'Correo', group: 'Operación' },
  { id: 'ssl', label: 'Certificados', group: 'Operación' },
  { id: 'backups', label: 'Backups', group: 'Operación' },
  { id: 'cron', label: 'Cron', group: 'Operación' },
  { id: 'ssh', label: 'SSH', group: 'Operación', requiresSsh: true },
  { id: 'monitor', label: 'Monitor', group: 'Operación' },
  { id: 'users', label: 'Usuarios', group: 'Administración', admin: true },
  { id: 'packages', label: 'Paquetes', group: 'Administración', admin: true },
  { id: 'security', label: 'Seguridad', group: 'Administración', admin: true },
  { id: 'filters', label: 'Antivirus y antispam', group: 'Administración', admin: true },
  { id: 'agent', label: 'Agente IA', group: 'Administración', admin: true },
  { id: 'firewall', label: 'Cortafuegos', group: 'Administración', admin: true },
  { id: 'programs', label: 'Programas', group: 'Administración', admin: true },
  { id: 'console', label: 'Consola', group: 'Administración', admin: true },
  { id: 'audit', label: 'Auditoría', group: 'Administración', admin: true },
  { id: 'system', label: 'Sistema', group: 'Administración' },
];

const NAV_ICON_PATHS = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  accounts: '<circle cx="9" cy="8" r="3"/><path d="M3 20a6 6 0 0 1 12 0"/><path d="M16 7a3 3 0 0 1 0 6"/><path d="M21 20a5 5 0 0 0-3-4.6"/>',
  websites: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18"/>',
  files: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  apps: '<path d="M12 3 4 7v10l8 4 8-4V7z"/><path d="M4 7l8 4 8-4"/><path d="M12 11v10"/>',
  installer: '<path d="m15 4 5 5"/><path d="M4 20 14 10"/><path d="m14 4 1.2 3.8L19 9l-3.8 1.2L14 14l-1.2-3.8L9 9l3.8-1.2z"/><path d="m19 14 .6 1.4L21 16l-1.4.6L19 18l-.6-1.4L17 16l1.4-.6z"/>',
  php: '<path d="m8 8-4 4 4 4"/><path d="m16 8 4 4-4 4"/><path d="m13 5-2 14"/>',
  databases: '<ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5"/><path d="M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/>',
  ftp: '<path d="M8 4v12"/><path d="m5 7 3-3 3 3"/><path d="M16 20V8"/><path d="m13 17 3 3 3-3"/>',
  dns: '<circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/><circle cx="5" cy="5" r="1.5"/><circle cx="19" cy="5" r="1.5"/><circle cx="5" cy="19" r="1.5"/><circle cx="19" cy="19" r="1.5"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  ssl: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  backups: '<path d="M12 3v12"/><path d="m8 11 4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
  cron: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  ssh: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><circle cx="16" cy="10" r="1.6"/><path d="m16 11.6 2.2 2.4"/>',
  monitor: '<path d="M3 12h4l2-6 3 12 2-6h7"/>',
  users: '<circle cx="9" cy="8" r="3"/><path d="M2 20a7 7 0 0 1 14 0"/><circle cx="17" cy="9" r="2"/><path d="M16 14a5 5 0 0 1 6 4"/>',
  packages: '<path d="M21 8 12 3 3 8v8l9 5 9-5z"/><path d="M3 8l9 5 9-5"/><path d="M12 13v8"/>',
  security: '<path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6z"/><path d="m9 12 2 2 4-4"/>',
  filters: '<path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6z"/><rect x="9" y="9" width="6" height="5" rx="1"/><path d="m9 10 3 2 3-2"/>',
  agent: '<rect x="4" y="7" width="16" height="12" rx="2"/><circle cx="9" cy="13" r="1"/><circle cx="15" cy="13" r="1"/><path d="M12 4v3"/><path d="M9 17h6"/>',
  firewall: '<path d="M12 3c3 4 6 6 6 10a6 6 0 0 1-12 0c0-2 1-3 2-5 0 2 1 3 2 3 0-3 1-5 2-8z"/>',
  programs: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/><path d="M8 13h8"/>',
  console: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M13 15h4"/>',
  audit: '<path d="M9 3h6l1 3h3v15H5V6h3z"/><path d="m9 13 2 2 4-4"/>',
  system: '<circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4M4.9 4.9 7 7M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1"/>',
};

function navIcon(id, label) {
  const paths = NAV_ICON_PATHS[id] || '<circle cx="12" cy="12" r="8"/>';
  return `<span class="nav-icon" role="img" aria-label="${esc(label)}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><title>${esc(label)}</title>${paths}</svg></span>`;
}

const TITLES = {
  databases: ['Bases de datos', 'MariaDB aislada por dominio, con usuario y contraseña propios'],
  ftp: ['FTP', 'Usuarios virtuales Pure-FTPd con chroot al home de la cuenta'],
  dns: ['DNS', 'Zonas autoritativas con SPF, DKIM, DMARC, MX y CAA'],
  backups: ['Backups', 'Copias de home, vhosts, pools y unidades con retención'],
  cron: ['Cron', 'Tareas programadas que se ejecutan con el usuario de la cuenta'],
  ssh: ['SSH', 'Acceso SSH con clave pública al usuario de la cuenta'],
  monitor: ['Monitor', 'Series históricas y estado de cada servicio'],
  security: ['Seguridad', 'Intentos de acceso, bloqueos y cadena de auditoría'],
  filters: ['Antivirus y antispam', 'ClamAV y SpamAssassin con el historial de detecciones y bloqueos'],
  agent: ['Agente IA', 'Análisis determinista del sistema con alertas de amenazas y errores'],
  firewall: ['Cortafuegos', 'Reglas nftables, IPs baneadas y listas blancas'],
  programs: ['Programas', 'Software instalado y actualizaciones del sistema'],
  console: ['Consola admin', 'Acciones privilegiadas auditadas y sin shell libre'],
  overview: ['Resumen', 'Estado del nodo y de los recursos gestionados'],
  accounts: ['Cuentas', 'Usuarios Linux aislados con cuota y home dedicado'],
  websites: ['Sitios web', 'Virtual hosts Nginx con TLS y reverse proxy'],
  files: ['Archivos', 'Gestor de archivos del document root del sitio'],
  apps: ['Aplicaciones', 'Procesos gestionados por systemd (Node, Python, Ruby, Java, .NET, Go)'],
  installer: ['Instalador', 'WordPress y Laravel en un sitio nuevo con PHP, base de datos y TLS'],
  php: ['PHP-FPM', 'Pools por cuenta con open_basedir y funciones restringidas'],
  mail: ['Correo', 'Dominios, buzones, webmail y seguridad DNS'],
  ssl: ['Certificados', 'Emisión y estado de certificados Let\'s Encrypt'],
  users: ['Usuarios del panel', 'Acceso al panel con roles y sesiones revocables'],
  packages: ['Paquetes', 'Planes de hosting y límites de recursos; 0 significa sin límite'],
  audit: ['Auditoría', 'Registro append-only encadenado por SHA-256'],
  system: ['Sistema', 'Información del nodo y reconciliación de estado'],
};

/* ---------------- utilities ---------------- */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(value) {
  return String(value === undefined || value === null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function td(html, cls = '') {
  return `<td class="${cls}">${html}</td>`;
}

const STATUS_LABELS = {
  active: 'activo', enabled: 'activo', suspended: 'suspendida', disabled: 'deshabilitado',
  stopped: 'detenida', failed: 'fallido', error: 'Error', ok: 'correcto',
  installed: 'instalado', absent: 'ausente', missing: 'Ausente', expiring: 'Por vencer',
  expired: 'Vencido', success: 'Correcto', blocked: 'Bloqueado', allow: 'Permitir',
  deny: 'Denegar', simulated: 'Simulado', pending: 'Pendiente', running: 'En ejecución',
  completed: 'Completado', 'brute-force': 'Fuerza bruta', security: 'Seguridad',
  normal: 'Normal', 'read-only': 'Solo lectura', 'read-write': 'Lectura/escritura',
  'no-mail': 'Sin correo', 'no-tls': 'Sin TLS', owner: 'Propietario',
  admin: 'Administrador', operator: 'Operador', viewer: 'Solo lectura',
  simulation: 'Simulación', production: 'Producción',
};

function statusLabel(value) {
  return STATUS_LABELS[value] || value;
}

function badge(text, kind = '') {
  return `<span class="badge ${kind}">${esc(statusLabel(text))}</span>`;
}

function btn(label, action, id = '', cls = 'tiny ghost', title = '') {
  return `<button class="btn ${cls}" data-action="${action}" data-id="${esc(id)}" title="${esc(title)}">${label}</button>`;
}

function programUnit(program) {
  if (program.unit) return program.unit;
  const name = String(program.name || '').toLowerCase();
  if (['nginx', 'mariadb', 'pure-ftpd', 'opendkim', 'fail2ban'].includes(name)) return name;
  if (name === 'bind9') return 'named';
  if (name === 'clamav') return 'clamav-daemon';
  if (name === 'clamav-milter') return 'clamav-milter';
  if (name === 'spamassassin') return 'spamd';
  if (name === 'spamass-milter') return 'spamass-milter';
  if (name.startsWith('php')) return name.replace('php-fpm ', 'php') + '-fpm';
  return '';
}

function programServiceBadge(program) {
  const status = program.service_status;
  if (!status) return '?';
  if (status === 'active') return badge('arrancado', 'ok');
  if (status === 'failed') return badge('fallido', 'bad');
  if (status === 'activating') return badge('arrancando', 'warn');
  if (status === 'deactivating') return badge('parando', 'warn');
  if (status === 'inactive' || status === 'dead') return badge('parado', 'warn');
  return badge(status, '');
}

function programButton(action, program, label, path) {
  const text = esc(T(label));
  return `<button class="btn tiny ghost" data-action="${action}" data-id="${esc(program)}" title="${text}" aria-label="${text}"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" role="img" aria-label="${text}"><title>${text}</title>${path}</svg></button>`;
}

function table(headers, rows, emptyText = 'Sin registros todavía.') {
  if (!rows.length) {
    return `<div class="card empty"><strong>Sin registros</strong><span>${esc(emptyText)}</span></div>`;
  }
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.join('')}</tr>`).join('');
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

const PAGE_SIZE = 20;

function paginateTables(root = document) {
  root.querySelectorAll('.table-wrap').forEach((wrap) => {
    const rows = Array.from(wrap.querySelectorAll('tbody tr'));
    let pager = wrap.nextElementSibling;
    if (!rows.length || rows.length <= PAGE_SIZE) {
      rows.forEach((row) => { row.style.display = ''; });
      if (pager && pager.classList.contains('table-pager')) pager.remove();
      delete wrap.dataset.page;
      return;
    }
    const pages = Math.ceil(rows.length / PAGE_SIZE);
    let page = Number(wrap.dataset.page) || 1;
    page = Math.min(Math.max(page, 1), pages);
    wrap.dataset.page = String(page);
    rows.forEach((row, index) => {
      row.style.display = index >= (page - 1) * PAGE_SIZE && index < page * PAGE_SIZE ? '' : 'none';
    });
    if (!pager || !pager.classList.contains('table-pager')) {
      pager = document.createElement('div');
      pager.className = 'table-pager';
      wrap.after(pager);
    }
    pager.innerHTML = `<button type="button" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>‹</button>` +
      `<span>${page} / ${pages}</span>` +
      `<button type="button" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>›</button>`;
    pager.querySelectorAll('button[data-page]').forEach((button) => {
      button.addEventListener('click', () => {
        wrap.dataset.page = button.dataset.page;
        paginateTables(root);
      });
    });
  });
}

function sectionHead(title, actionHtml = '') {
  return `<div class="section-head"><h2>${esc(title)}</h2><div>${actionHtml}</div></div>`;
}

function fmtDate(raw) {
  if (!raw) return '—';
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return esc(raw);
  return date.toLocaleString();
}

function fmtUptime(secs) {
  const value = Number(secs) || 0;
  const d = Math.floor(value / 86400);
  const h = Math.floor((value % 86400) / 3600);
  const m = Math.floor((value % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

function fmtKb(kb) {
  const value = Number(kb) || 0;
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} GiB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} MiB`;
  return `${value} KiB`;
}

function pct(used, total) {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((used / total) * 100)));
}

function runtimeLabel(runtime) {
  if (!runtime) return '—';
  const meta = RUNTIMES[runtime.engine] || { short: runtime.engine };
  return runtime.version ? `${meta.short} ${runtime.version}` : meta.short;
}

function val(form, name) {
  const el = form.elements[name];
  return el ? String(el.value || '').trim() : '';
}

function num(form, name, fallback = 0) {
  const parsed = Number(val(form, name));
  return Number.isFinite(parsed) ? parsed : fallback;
}

function bool(form, name) {
  const el = form.elements[name];
  return !!(el && el.checked);
}

function T(text) {
  return window.RYNX_I18N ? window.RYNX_I18N.tr(text) : text;
}

function toAsciiDomain(value) {
  const raw = String(value || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '');
  if (!raw) return '';
  try {
    return new URL(`http://${raw}`).hostname.replace(/\.$/, '');
  } catch {
    return raw.toLowerCase();
  }
}

function toAsciiEmail(value) {
  const raw = String(value || '').trim();
  const at = raw.lastIndexOf('@');
  if (at <= 0) return raw;
  return `${raw.slice(0, at + 1)}${toAsciiDomain(raw.slice(at + 1))}`;
}

function TF(text, vars = {}) {
  let out = T(text);
  for (const [key, value] of Object.entries(vars)) {
    out = out.split(`{${key}}`).join(String(value));
  }
  return out;
}

function humanizeError(message) {
  const text = String(message || '');
  const match = /^the package limit for websites and apps has been reached \((\d+)\)$/.exec(text);
  if (match) return TF('El paquete ha alcanzado el límite de sitios y apps ({limit}).', { limit: match[1] });
  return text;
}

const nativeConfirm = window.confirm.bind(window);
window.confirm = (message) => nativeConfirm(T(String(message)));

function translateUi(root) {
  if (window.RYNX_I18N) window.RYNX_I18N.translateDom(root || document.body);
}

function toast(message, kind = 'ok') {
  const root = $('#toasts');
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  const title = kind === 'error' ? T('Error') : T('Hecho');
  el.innerHTML = `<div class="t-title">${esc(title)}</div><div>${esc(T(humanizeError(message)))}</div>`;
  root.appendChild(el);
  setTimeout(() => el.remove(), kind === 'error' ? 7000 : 3500);
}

/* ---------------- API ---------------- */

async function api(path, options = {}) {
  const method = options.method || 'GET';
  const headers = {};
  if (options.body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && S.csrf) headers['x-csrf-token'] = S.csrf;

  const response = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  const text = await response.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = null; }
  }

  if (response.status === 401) {
    showLogin();
    throw new Error('La sesión ha expirado');
  }
  if (!response.ok) {
    const message = data && data.error && data.error.message
      ? data.error.message
      : TF('Error HTTP {status}', { status: response.status });
    throw new Error(message);
  }
  return data;
}

async function publicPost(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(data && data.error ? data.error.message : TF('Error HTTP {status}', { status: response.status }));
  }
  return data;
}

/* ---------------- session ---------------- */

function showLoginForm(mode = 'login') {
  const login = $('#login-form');
  const forgot = $('#forgot-form');
  const reset = $('#reset-form');
  const twofa = $('#twofa-form');
  if (!login || !forgot || !reset) return;
  login.classList.toggle('hidden', mode !== 'login');
  forgot.classList.toggle('hidden', mode !== 'forgot');
  reset.classList.toggle('hidden', mode !== 'reset');
  if (twofa) twofa.classList.add('hidden');
  translateUi(document.body);
  const form = mode === 'reset' ? reset : mode === 'forgot' ? forgot : login;
  const field = mode === 'login' ? 'username' : mode === 'forgot' ? 'email' : 'password';
  const input = form.elements[field];
  if (input) setTimeout(() => input.focus(), 30);
}

function showTwoFactor(email, challenge) {
  S.twoFactorChallenge = challenge;
  $('#login-form').classList.add('hidden');
  $('#forgot-form').classList.add('hidden');
  $('#reset-form').classList.add('hidden');
  $('#twofa-form').classList.remove('hidden');
  const target = $('#twofa-email');
  if (target) target.textContent = email || T('tu email');
  const input = $('#twofa-form').elements.code;
  if (input) {
    input.value = '';
    setTimeout(() => input.focus(), 30);
  }
  translateUi(document.body);
}

function showLogin() {
  S.user = null;
  S.csrf = null;
  S.impersonatedBy = null;
  S.twoFactorChallenge = null;
  S.data = { accounts: [], websites: [], apps: [], pools: [], certs: [], users: [] };
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  showLoginForm(S.resetToken ? 'reset' : 'login');
}

function persistUserLocale(locale) {
  if (!S.user || !S.csrf || !locale) return;
  S.user.locale = locale;
  api('/api/v1/auth/locale', { method: 'PUT', body: { locale } }).catch(() => {});
}

function applyUserLocale(user) {
  if (!window.RYNX_I18N) return;
  const saved = user && user.locale;
  if (!saved) {
    persistUserLocale(window.RYNX_I18N.getLanguage());
    return;
  }
  if (window.RYNX_I18N.getLanguage() !== saved) {
    window.RYNX_I18N.setLanguage(saved, false);
  }
}

function enterApp() {
  applyUserLocale(S.user);
  S.data = { accounts: [], websites: [], apps: [], pools: [], certs: [], users: [] };
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#user-name').textContent = S.user.username;
  $('#user-role').textContent = statusLabel(S.user.role);
  $('#avatar').textContent = S.user.username.slice(0, 1);
  const banner = $('#impersonation');
  if (banner) {
    banner.classList.toggle('hidden', !S.impersonatedBy);
    const target = $('#impersonated-name');
    if (target) target.textContent = S.user.username;
  }
  buildNav();
  if (isScoped()) {
    const mode = $('#mode-badge');
    if (mode) {
      mode.textContent = 'cliente';
      mode.className = 'badge';
    }
  }
  navigate(isScoped() ? 'accounts' : 'overview');
  if (isScoped()) loadList('certs').then(updateCertAlert).catch(() => {});
}

function isAdmin() {
  return S.user && (S.user.role === 'owner' || S.user.role === 'admin');
}

function isScoped() {
  return Boolean(S.user && S.user.account);
}

function canWrite() {
  return Boolean(S.user && ['owner', 'admin', 'operator'].includes(S.user.role));
}

const SCOPED_NAV = new Set([
  'accounts',
  'websites',
  'files',
  'apps',
  'installer',
  'php',
  'databases',
  'ftp',
  'dns',
  'mail',
  'ssl',
  'backups',
  'cron',
  'ssh',
]);

function buildNav() {
  const nav = $('#nav');
  let html = '';
  let group = '';
  for (const item of NAV_ITEMS) {
    if (isScoped() && !SCOPED_NAV.has(item.id)) continue;
    if (item.requiresSsh && (!isScoped() || !S.sshEnabled)) continue;
    if (item.admin && !isAdmin()) continue;
    if (item.group !== group) {
      group = item.group;
      html += `<div class="nav-group">${esc(group)}</div>`;
    }
    const label = item.id === 'accounts' && isScoped() ? 'Mi cuenta' : item.label;
    html += `<button data-view="${item.id}" title="${esc(label)}" aria-label="${esc(label)}">${navIcon(item.id, label)}</button>`;
  }
  nav.innerHTML = html;
  $$('#nav button').forEach((button) => {
    button.addEventListener('click', () => navigate(button.dataset.view));
  });
}

async function boot() {
  try {
    const response = await fetch('/api/v1/auth/me', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('unauthenticated');
    const data = await response.json();
    S.user = data.user;
    S.csrf = data.csrf_token;
    S.impersonatedBy = data.impersonated_by || null;
    S.sshEnabled = Boolean(data.ssh_enabled);
    enterApp();
  } catch {
    showLogin();
  }
}

/* ---------------- navigation ---------------- */

const renderers = {
  databases: renderDatabases,
  ftp: renderFtp,
  mail: renderMail,
  dns: renderDns,
  backups: renderBackups,
  cron: renderCron,
  ssh: renderSsh,
  monitor: renderMonitor,
  security: renderSecurity,
  filters: renderFilters,
  agent: renderAgent,
  firewall: renderFirewall,
  programs: renderPrograms,
  console: renderConsole,
  overview: renderOverview,
  accounts: renderAccounts,
  websites: renderWebsites,
  files: renderFiles,
  apps: renderApps,
  installer: renderInstaller,
  php: renderPhp,
  ssl: renderSsl,
  users: renderUsers,
  packages: renderPackages,
  audit: renderAudit,
  system: renderSystem,
};

async function navigate(id, silent = false) {
  if (!renderers[id]) id = 'overview';
  if (agentPollTimer) {
    clearTimeout(agentPollTimer);
    agentPollTimer = null;
  }
  S.current = id;
  const token = ++S.navToken;
  $$('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.view === id));
  const [title, subtitle] = TITLES[id];
  $('#view-title').textContent = title;
  $('#view-subtitle').textContent = subtitle;
  if (!silent) $('#view').innerHTML = `<div class="loading">${T('Cargando…')}</div>`;
  const previousPage = silent ? $('#view .table-wrap')?.dataset.page : null;
  try {
    await renderers[id]();
    translateUi(document.body);
    if (previousPage) {
      const wrap = $('#view .table-wrap');
      if (wrap) wrap.dataset.page = previousPage;
    }
    paginateTables();
    updateCertAlert();
  } catch (err) {
    if (token !== S.navToken) return;
    $('#view').innerHTML = `<div class="card empty"><strong>No se pudo cargar la vista</strong><span>${esc(err.message)}</span></div>`;
    translateUi(document.body);
  } finally {
    if (id === 'agent' && token === S.navToken) scheduleAgentPoll();
  }
}

function scheduleAgentPoll() {
  if (agentPollTimer) clearTimeout(agentPollTimer);
  agentPollTimer = setTimeout(() => {
    agentPollTimer = null;
    if (S.current !== 'agent') return;
    if (document.hidden) {
      scheduleAgentPoll();
      return;
    }
    navigate('agent', true);
  }, AGENT_POLL_MS);
}

async function refresh() {
  await navigate(S.current);
  if (S.current !== 'overview' && S.current !== 'ssl') {
    loadList('certs').then(updateCertAlert).catch(() => {});
  }
}

/* ---------------- data loaders ---------------- */

const LIST_ENDPOINTS = {
  accounts: ['/api/v1/accounts', 'accounts'],
  websites: ['/api/v1/websites', 'websites'],
  apps: ['/api/v1/apps', 'apps'],
  pools: ['/api/v1/php-pools', 'pools'],
  certs: ['/api/v1/certs', 'certs'],
  databases: ['/api/v1/databases', 'databases'],
  ftp: ['/api/v1/ftp', 'accounts'],
  backups: ['/api/v1/backups', 'backups'],
  cron: ['/api/v1/cron', 'jobs'],
  dns: ['/api/v1/dns', 'zones'],
  programs: ['/api/v1/system/programs', 'programs'],
  updates: ['/api/v1/system/updates', 'updates'],
  users: ['/api/v1/users', null],
  packages: ['/api/v1/packages', null],
  accountPackages: ['/api/v1/packages/assignments', null],
  mailDomains: ['/api/v1/mail/domains', 'domains'],
  mailAccounts: ['/api/v1/mail/accounts', 'accounts'],
};

async function loadList(key) {
  const [url, field] = LIST_ENDPOINTS[key];
  const data = await api(url);
  S.data[key] = field ? (data[field] || []) : (Array.isArray(data) ? data : []);
  return S.data[key];
}

async function loadSystem() {
  const data = await api('/api/v1/system');
  S.system = data.info;
  S.mode = data.info.mode;
  updateModeBadge();
  return S.system;
}

function updateModeBadge() {
  const el = $('#mode-badge');
  if (!el) return;
  if (S.mode === 'simulation') {
    el.textContent = 'simulación';
    el.className = 'badge warn';
    el.title = 'No se toca el sistema operativo real';
  } else if (S.mode === 'linux') {
    el.textContent = 'linux';
    el.className = 'badge ok';
    el.title = 'Daemon privilegiado sobre systemd/nginx';
  } else {
    el.textContent = S.mode || 'conectando';
    el.className = 'badge';
  }
}

/* ---------------- modal ---------------- */

function openModal(options) {
  const root = $('#modal-root');
  const submitLabel = options.submitLabel || 'Guardar';
  const danger = options.danger ? 'danger' : 'primary';
  root.innerHTML = `
    <div class="modal-backdrop" data-backdrop>
      <div class="modal" role="dialog" aria-modal="true">
        <h2>${esc(options.title)}</h2>
        <form id="modal-form">
          ${options.html}
          <div class="modal-actions">
            <button type="button" class="btn ghost" data-close>Cancelar</button>
            <button type="submit" class="btn ${danger}">${esc(submitLabel)}</button>
          </div>
        </form>
      </div>
    </div>`;

  translateUi(root);
  paginateTables(root);
  const form = $('#modal-form');
  const close = () => { root.innerHTML = ''; };

  root.querySelector('[data-close]').addEventListener('click', close);
  root.querySelector('[data-backdrop]').addEventListener('click', (event) => {
    if (event.target === event.currentTarget) close();
  });
  const onKey = (event) => {
    if (event.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); }
  };
  document.addEventListener('keydown', onKey);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      await options.onSubmit(form);
      document.removeEventListener('keydown', onKey);
      // A submit handler may have replaced the modal (e.g. showOutput).
      if (root.contains(form)) close();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      submit.disabled = false;
    }
  });

  if (options.onMount) options.onMount(form);
  const first = form.querySelector('input, select, textarea');
  if (first) setTimeout(() => first.focus(), 30);
}

function field(name, label, html, help = '', full = false) {
  return `<label class="field ${full ? 'full' : ''}"><span>${esc(label)}</span>${html}${help ? `<small class="hint">${esc(help)}</small>` : ''}</label>`;
}

function fInput(name, label, opts = {}) {
  const type = opts.type || 'text';
  const attrs = [
    `name="${esc(name)}"`,
    `type="${esc(type)}"`,
    opts.value !== undefined ? `value="${esc(opts.value)}"` : '',
    opts.placeholder ? `placeholder="${esc(opts.placeholder)}"` : '',
    opts.required ? 'required' : '',
    opts.min !== undefined ? `min="${esc(opts.min)}"` : '',
    opts.max !== undefined ? `max="${esc(opts.max)}"` : '',
    opts.step !== undefined ? `step="${esc(opts.step)}"` : '',
    opts.autocomplete ? `autocomplete="${esc(opts.autocomplete)}"` : '',
    opts.list ? `list="${esc(opts.list)}"` : '',
  ].filter(Boolean).join(' ');
  return field(name, label, `<input ${attrs}>`, opts.help, opts.full);
}

function fSelect(name, label, options, opts = {}) {
  const items = options.map((option) => {
    const value = typeof option === 'string' ? option : option.value;
    const text = typeof option === 'string' ? option : option.label;
    const selected = opts.value !== undefined && String(opts.value) === String(value) ? ' selected' : '';
    return `<option value="${esc(value)}"${selected}>${esc(text)}</option>`;
  }).join('');
  return field(name, label, `<select name="${esc(name)}">${items}</select>`, opts.help, opts.full);
}

function fCheck(name, label, checked = true) {
  return `<label class="check"><input type="checkbox" name="${esc(name)}" ${checked ? 'checked' : ''}><span>${esc(label)}</span></label>`;
}

function fTextarea(name, label, opts = {}) {
  return field(name, label, `<textarea name="${esc(name)}" placeholder="${esc(opts.placeholder || '')}">${esc(opts.value || '')}</textarea>`, opts.help, opts.full);
}

/* ---------------- package helpers ---------------- */

const UNLIMITED_DISK_MB = 10485760;

function limitText(value) {
  return Number(value) === 0 ? T('Sin límite') : String(value);
}

function diskText(mb) {
  return Number(mb) >= UNLIMITED_DISK_MB ? T('Sin límite') : `${mb} MB`;
}

function packageSummary(pkg) {
  if (!pkg) return '';
  const rows = [
    ['Cuenta', diskText(pkg.account_mb)],
    ['Ancho de banda', limitText(pkg.bandwidth_mb)],
    ['Backups', pkg.backups],
    ['Dominios webs - apps', limitText(pkg.web_domains)],
    ['Alias web', limitText(pkg.web_aliases)],
    ['Dominios de email', limitText(pkg.mail_domains)],
    ['Cuentas de email', limitText(pkg.mail_accounts)],
    ['Tasa de correo', limitText(pkg.mail_rate_limit)],
    ['Bases de datos', limitText(pkg.databases)],
    ['Cuentas FTP', limitText(pkg.ftp_accounts)],
    ['Zonas DNS', limitText(pkg.dns_zones)],
    ['Registros DNS', limitText(pkg.dns_records)],
    ['BD del sistema', limitText(pkg.system_databases)],
  ];
  return `<div class="package-summary">${rows.map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('')}</div>`;
}

function formSection(title, help = '') {
  return `<div class="form-section"><h3>${esc(title)}</h3>${help ? `<p class="hint">${esc(help)}</p>` : ''}</div>`;
}

function pkgNumber(name, label, opts = {}) {
  const min = opts.min === undefined ? 0 : opts.min;
  const max = opts.max === undefined ? 1000 : opts.max;
  const value = opts.value === undefined ? 1 : opts.value;
  const disabled = opts.disabled ? ' disabled' : '';
  const input = `<div class="limit-row"><input name="${esc(name)}" type="number" min="${min}" max="${max}" step="1" value="${esc(value)}"${disabled}>` +
    (opts.unlimited === false ? '' : `<button type="button" class="btn tiny ghost" data-limit="${esc(name)}"${disabled}>${esc(T('Sin límite'))}</button>`) +
    '</div>';
  return field(name, label, input, opts.help, opts.full);
}

/* ---------------- shared cell builders ---------------- */

function accountOptions(includeEmpty = false) {
  let items = S.data.accounts.map((a) => ({
    value: a.spec.username,
    label: `${a.spec.username}${a.spec.enabled ? '' : ' ' + T('(suspendida)')}`,
  }));
  if (S.user && S.user.account) {
    items = items.filter((item) => item.value === S.user.account);
  }
  if (includeEmpty) items.unshift({ value: '', label: '- selecciona -' });
  return items;
}

function statusBadge(enabled) {
  return enabled ? badge('activa', 'ok') : badge('suspendida', 'warn');
}

function certBadge(status) {
  const map = { active: 'ok', expiring: 'warn', expired: 'bad', missing: 'warn', error: 'bad' };
  return badge(status, map[status] || '');
}

const CERT_ATTENTION = new Set(['expiring', 'expired', 'missing', 'error']);

function certProblems() {
  return (S.data.certs || []).filter((cert) => CERT_ATTENTION.has(cert.status));
}

function updateCertAlert() {
  const el = $('#cert-alert');
  if (!el) return;
  const problems = certProblems();
  if (!problems.length) {
    el.classList.add('hidden');
    return;
  }
  const critical = problems.some((cert) => cert.status === 'expired' || cert.status === 'error');
  const preview = problems.slice(0, 3).map((cert) => `${cert.domain} (${cert.status})`).join(', ');
  el.classList.remove('hidden');
  el.classList.toggle('critical', critical);
  const text = $('#cert-alert-text');
  if (text) {
    text.innerHTML = `${esc(T('Certificados que requieren atención'))}: ${problems.length}
      <span class="mono small">${esc(preview)}${problems.length > 3 ? '…' : ''}</span>`;
  }
  const button = $('#cert-alert-review');
  if (button) button.textContent = T('Revisar certificados');
}

/* ---------------- overview ---------------- */

async function renderOverview() {
  const results = await Promise.allSettled([
    loadList('accounts'),
    loadList('websites'),
    loadList('apps'),
    loadList('certs'),
    loadSystem(),
  ]);
  const failed = results.filter((r) => r.status === 'rejected');
  const system = S.system;

  const stats = [
    ['Cuentas', S.data.accounts.length, 'usuarios Linux gestionados'],
    ['Sitios web', S.data.websites.length, 'virtual hosts Nginx'],
    ['Aplicaciones', S.data.apps.length, 'procesos systemd'],
    ['Certificados', S.data.certs.filter((c) => c.status === 'active').length, 'activos'],
  ];

  let html = `<div class="grid cols-4">${stats.map(([label, value, hint]) => `
    <div class="card stat">
      <div class="label">${esc(label)}</div>
      <div class="value">${esc(value)}</div>
      <div class="hint">${esc(hint)}</div>
    </div>`).join('')}</div>`;

  if (system) {
    const memUsed = system.mem_total_kb - system.mem_available_kb;
    const diskUsed = system.disk_total_kb - system.disk_available_kb;
    html += `
      <div class="grid cols-2">
        <div class="card">
          <div class="section-head"><h2>Nodo</h2>${badge(system.mode, system.mode === 'simulation' ? 'warn' : 'ok')}</div>
          <dl class="kv" style="margin-top:14px">
            <dt>Hostname</dt><dd>${esc(system.hostname)}</dd>
            <dt>Sistema</dt><dd>${esc(system.os)}</dd>
            <dt>Kernel</dt><dd>${esc(system.kernel)}</dd>
            <dt>Uptime</dt><dd>${esc(fmtUptime(system.uptime_secs))}</dd>
            <dt>CPU</dt><dd>${esc(system.cpu_count)} vCPU</dd>
            <dt>Load (1/5/15)</dt><dd>${(system.load || [0, 0, 0]).map((v) => (v / 100).toFixed(2)).join(' / ')}</dd>
            <dt>Daemon</dt><dd>v${esc(system.daemon_version)}</dd>
          </dl>
        </div>
        <div class="card">
          <div class="section-head"><h2>Recursos</h2></div>
          <div style="margin-top:16px" class="stack">
            <div>
              <div class="muted small">Memoria · ${esc(fmtKb(memUsed))} de ${esc(fmtKb(system.mem_total_kb))}</div>
              <div class="bar" style="margin-top:6px"><i style="width:${pct(memUsed, system.mem_total_kb)}%"></i></div>
            </div>
            <div>
              <div class="muted small">Disco · ${esc(fmtKb(diskUsed))} de ${esc(fmtKb(system.disk_total_kb))}</div>
              <div class="bar" style="margin-top:6px"><i style="width:${pct(diskUsed, system.disk_total_kb)}%"></i></div>
            </div>
          </div>
        </div>
      </div>`;
  } else {
    html += `<div class="card empty"><strong>Daemon no disponible</strong><span>No se pudo leer el estado del nodo. Revisa rynxd.</span></div>`;
  }

  if (isAdmin()) {
    try {
      const data = await api('/api/v1/audit?limit=8');
      const rows = (data.entries || []).slice().reverse().map((entry) => [
        td(`<span class="chip">#${esc(entry.seq)}</span>`),
        td(esc(fmtDate(entry.at))),
        td(`<strong>${esc(entry.actor)}</strong>`),
        td(`<span class="mono small">${esc(entry.action)}</span>`),
        td(esc(entry.target)),
      ]);
      html += sectionHead('Actividad reciente');
      html += table(['#', 'Fecha', 'Actor', 'Acción', 'Objetivo'], rows, 'Sin actividad registrada.');
    } catch {
      /* daemon may be down; overview already reported it */
    }
  }

  if (failed.length) {
    html += `<p class="muted small">${TF('{count} consulta(s) fallaron al cargar el resumen.', { count: failed.length })}</p>`;
  }
  $('#view').innerHTML = html;
}

/* ---------------- accounts ---------------- */

async function renderAccounts() {
  await loadList('accounts');
  if (isAdmin() && !isScoped()) await loadList('users');
  if (!isScoped() && canWrite()) await loadList('packages');
  await loadList('accountPackages');
  const scoped = isScoped();
  let myPackage = null;
  if (scoped) {
    try {
      myPackage = await api('/api/v1/packages/me');
    } catch (err) {
      myPackage = null;
    }
  }
  const assignments = new Map((S.data.accountPackages || []).map((item) => [item.account, item]));
  const rows = S.data.accounts.map((account) => {
    const spec = account.spec;
    const assignment = assignments.get(spec.username);
    const panelUser = isAdmin() && !scoped
      ? (S.data.users || []).find((user) => user.account === spec.username)
      : null;
    const actions = [];
    if (assignment && canWrite()) {
      actions.push(btn('Backend', 'account-backend', spec.username, 'tiny ghost'));
      if (!scoped) actions.push(btn('Límites', 'account-limits', spec.username, 'tiny ghost'));
    }
    if (isAdmin() && !scoped) {
      actions.push(panelUser
        ? btn('Entrar', 'impersonate', panelUser.username, 'tiny ghost')
        : btn('Crear acceso', 'account-panel-access', spec.username, 'tiny ghost'));
    }
    if (!scoped) {
      actions.push(btn(spec.enabled ? 'Suspender' : 'Activar', 'account-toggle', spec.username));
      actions.push(btn('SSH', 'account-ssh', spec.username, 'tiny ghost'));
      actions.push(btn('Eliminar', 'account-delete', spec.username, 'tiny danger'));
    }
    return [
      td(`<div class="cell-title">${esc(spec.username)}</div><div class="cell-sub">${esc(spec.email)}</div>`),
      td(assignment ? `<div class="cell-title">${esc(assignment.package_name)}</div><div class="cell-sub">${esc(assignment.web_backend)}</div>` : '<span class="muted">—</span>'),
      td(`<span class="chip">UID ${esc(account.uid)}</span>`),
      td(esc(diskText(spec.disk_limit_mb))),
      td(spec.php_version ? `PHP ${esc(spec.php_version)}` : '<span class="muted">—</span>'),
      td(statusBadge(spec.enabled)),
      td(spec.ssh_enabled ? badge('Sí', 'ok') : badge('No', '')),
      td(`<span class="mono small">${esc(account.home)}</span>`),
      td(actions.join(''), 'actions'),
    ];
  });

  const createButton = !scoped && canWrite()
    ? '<button class="btn primary" data-action="account-new">Nueva cuenta</button>'
    : '';
  let html = sectionHead(scoped ? 'Mi cuenta' : 'Cuentas de hosting', createButton) +
    table(['Cuenta', 'Paquete', 'UID', 'Disco', 'PHP', 'Estado', 'SSH', 'Home', ''], rows,
      scoped ? 'No tienes una cuenta vinculada.' : 'Crea la primera cuenta para empezar.');
  if (scoped && myPackage) {
    html += `<div class="card" style="margin-top:16px">
      <div class="section-head"><h2>Límites · ${esc(myPackage.name)}</h2></div>
      ${packageSummary(myPackage)}
    </div>`;
  }
  $('#view').innerHTML = html;
}

async function loadPhpVersions() {
  if (S.phpVersions) return S.phpVersions;
  try {
    const data = await api('/api/v1/php/versions');
    S.phpVersions = Array.isArray(data.versions) ? data.versions : [];
  } catch {
    S.phpVersions = [];
  }
  return S.phpVersions;
}

async function openAccountModal() {
  const packages = S.data.packages || [];
  const phpVersions = await loadPhpVersions();
  if (!packages.length) {
    toast('Primero crea un paquete en Administración > Paquetes', 'error');
    return;
  }
  const defaultPackage = packages.find((pkg) => pkg.is_default) || packages[0];
  openModal({
    title: 'Nueva cuenta de hosting',
    submitLabel: 'Crear cuenta',
    html: `<div class="form-grid">
      ${fInput('username', 'Usuario del sistema', { required: true, placeholder: 'acme', help: 'minúsculas, 3-24 caracteres; se crea un usuario Linux' })}
      ${fInput('email', 'Email', { type: 'email', required: true, placeholder: 'admin@example.com' })}
      ${fSelect('package_id', 'Paquete', packages.map((pkg) => ({ value: pkg.id, label: pkg.name })), { value: defaultPackage.id, help: 'Los límites del paquete quedan bloqueados para esta cuenta.' })}
      ${fSelect('web_backend', 'Backend plantilla', WEB_BACKEND_OPTIONS, { value: defaultPackage.web_backend, help: 'Preseleccionado por el paquete; puedes cambiarlo.' })}
      <div class="field full"><span>Límites del paquete</span><div id="package-summary"></div></div>
      ${fSelect('php_version', 'PHP por defecto', [{ value: '', label: '— sin pool —' }, ...phpVersions.map((v) => ({ value: v, label: `PHP ${v}` }))], { value: phpVersions[0] || '' })}
      <div class="full">${fCheck('enabled', 'Cuenta activa', true)}</div>
      <div class="full">${fCheck('ssh_enabled', 'Permitir acceso SSH (solo clave pública)', false)}</div>
      ${fSelect('panel_access', 'Acceso al panel del cliente', [
        { value: 'viewer', label: 'Solo lectura (viewer)' },
        { value: 'operator', label: 'Operador (gestiona su cuenta)' },
        { value: 'none', label: 'Sin acceso al panel' },
      ], { value: 'viewer', help: 'El operador puede gestionar los recursos de su propia cuenta; el viewer es solo lectura.' })}
    </div>`,
    onMount: (form) => {
      const packageSelect = form.elements.package_id;
      const backend = form.elements.web_backend;
      const summary = form.querySelector('#package-summary');
      const sync = () => {
        const pkg = packages.find((item) => item.id === packageSelect.value);
        if (!pkg) {
          summary.innerHTML = '';
          return;
        }
        backend.value = pkg.web_backend;
        summary.innerHTML = packageSummary(pkg);
        translateUi(summary);
      };
      packageSelect.addEventListener('change', sync);
      sync();
    },
    onSubmit: async (form) => {
      const pkg = packages.find((item) => item.id === val(form, 'package_id'));
      if (!pkg) throw new Error('Selecciona un paquete');
      const access = val(form, 'panel_access');
      const body = {
        username: val(form, 'username').toLowerCase(),
        email: toAsciiEmail(val(form, 'email')),
        disk_limit_mb: pkg.account_mb,
        php_version: val(form, 'php_version') || null,
        enabled: bool(form, 'enabled'),
        ssh_enabled: bool(form, 'ssh_enabled'),
        package_id: pkg.id,
        web_backend: val(form, 'web_backend'),
        panel_access: access !== 'none',
      };
      if (access !== 'none') body.panel_role = access;
      const result = await api('/api/v1/accounts', { method: 'POST', body });
      if (result.panel_password) {
        showOutput(
          T('Cuenta y acceso creados'),
          `${T('usuario del panel:')} ${result.panel_user.username}\n` +
            `${T('contraseña:')} ${result.panel_password}\n\n` +
            `${T('Entra en')} ${location.origin} ${T('con esas credenciales.')}\n` +
            T('Guarda la contraseña ahora; no se volverá a mostrar.'),
        );
      } else {
        toast('Cuenta creada');
      }
      await refresh();
    },
  });
}

function openBackendModal(account) {
  const assignment = (S.data.accountPackages || []).find((item) => item.account === account);
  if (!assignment) {
    toast('La cuenta no tiene un paquete asignado', 'error');
    return;
  }
  openModal({
    title: T('Backend plantilla') + ' · ' + account,
    submitLabel: 'Guardar',
    html: `<div class="form-grid">
      ${fSelect('web_backend', 'Backend plantilla', WEB_BACKEND_OPTIONS, { value: assignment.web_backend, help: 'Solo cambia el backend web; el resto del paquete sigue bloqueado.' })}
    </div>`,
    onSubmit: async (form) => {
      await api(`/api/v1/packages/assignments/${encodeURIComponent(account)}`, {
        method: 'PATCH',
        body: { web_backend: val(form, 'web_backend') },
      });
      toast('Backend actualizado');
      await refresh();
    },
  });
}

/* ---------------- websites ---------------- */

async function renderWebsites() {
  await Promise.all([loadList('websites'), loadList('accounts'), loadList('apps'), loadList('accountPackages')]);
  const writable = canWrite();
  const rows = S.data.websites.map((website) => {
    const spec = website.spec;
    const aliases = spec.aliases && spec.aliases.length
      ? `<div class="cell-sub">+ ${esc(spec.aliases.join(', '))}</div>` : '';
    return [
      td(`<div class="cell-title">${esc(spec.domain)}</div>${aliases}`),
      td(esc(spec.username)),
      td(`<span class="chip">${esc(runtimeLabel(spec.runtime))}</span>${spec.app ? `<div class="cell-sub">app: ${esc(spec.app)}</div>` : ''}`),
      td(spec.tls === 'disabled' ? badge('sin tls', 'warn') : badge(spec.tls === 'lets_encrypt' ? 'let\'s encrypt' : 'manual', 'info')),
      td(spec.enabled ? badge('activo', 'ok') : badge('deshabilitado', 'warn')),
      td(`<span class="mono small">${esc(spec.docroot)}</span>`),
      td([
        btn('Archivos', 'website-files', spec.domain),
        writable ? btn('Editar', 'website-edit', spec.domain) : '',
        writable ? btn('Eliminar', 'website-delete', spec.domain, 'tiny danger') : '',
      ].filter(Boolean).join(' '), 'actions'),
    ];
  });

  $('#view').innerHTML =
    sectionHead('Sitios web', writable ? `<button class="btn primary" data-action="website-new">Nuevo sitio</button>` : '') +
    table(['Dominio', 'Cuenta', 'Runtime', 'TLS', 'Estado', 'Docroot', ''], rows, 'Aún no hay virtual hosts.');
}

async function openWebsiteModal(website = null) {
  if (!S.data.accounts.length) {
    toast('Primero crea una cuenta de hosting', 'error');
    return;
  }
  const editing = Boolean(website);
  const spec = website ? website.spec : null;
  const phpVersions = await loadPhpVersions();
  const engineOptions = ['static', 'php', ...MANAGED].map((engine) => ({
    value: engine,
    label: RUNTIMES[engine].label,
  }));
  const accountItems = accountOptions(false);
  const initialEngine = spec ? spec.runtime.engine : 'php';
  const initialVersions = initialEngine === 'php'
    ? (spec && spec.runtime.version && !phpVersions.includes(spec.runtime.version)
      ? [spec.runtime.version, ...phpVersions] : phpVersions)
    : ((RUNTIMES[initialEngine] && RUNTIMES[initialEngine].versions) || []);

  openModal({
    title: editing ? T('Editar') + ' · ' + spec.domain : 'Nuevo sitio web',
    submitLabel: editing ? 'Guardar cambios' : 'Publicar sitio',
    html: `<div class="form-grid">
      ${fInput('domain', 'Dominio', { value: spec ? spec.domain : '', required: true, placeholder: 'example.com', help: 'se valida y normaliza en el daemon' })}
      ${fInput('aliases', 'Alias', { value: spec ? spec.aliases.join(', ') : '', placeholder: 'www.example.com, cdn.example.com', help: 'separados por coma' })}
      ${fSelect('username', 'Cuenta', accountItems, { value: spec ? spec.username : undefined, required: true })}
      ${fSelect('engine', 'Runtime', engineOptions, { value: initialEngine })}
      ${fSelect('version', 'Versión', initialVersions.map((v) => ({ value: v, label: v })), { value: spec ? spec.runtime.version : (initialVersions[0] || '') })}
      ${fSelect('app', 'Aplicación', [{ value: '', label: '— selecciona —' }], { value: spec && spec.app ? spec.app : '', help: 'obligatoria para runtimes gestionados' })}
      ${fInput('docroot', 'Document root', { value: spec ? spec.docroot : 'public_html', required: true, help: 'relativo al home de la cuenta' })}
      ${fSelect('tls', 'TLS', [
        { value: 'disabled', label: 'Sin TLS' },
        { value: 'lets_encrypt', label: "Let's Encrypt" },
        { value: 'manual', label: 'Certificado manual' },
      ], { value: spec ? spec.tls : 'lets_encrypt' })}
      <div class="full">${fCheck('force_https', 'Redirigir HTTP a HTTPS', spec ? spec.force_https : true)}</div>
      <div class="full">${fCheck('enabled', 'Sitio activo', spec ? spec.enabled : true)}</div>
    </div>`,
    onMount: (form) => {
      const engine = form.elements.engine;
      const version = form.elements.version;
      const app = form.elements.app;
      const username = form.elements.username;

      const syncVersions = () => {
        const versions = engine.value === 'php'
          ? phpVersions
          : ((RUNTIMES[engine.value] && RUNTIMES[engine.value].versions) || []);
        version.innerHTML = versions.length
          ? versions.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join('')
          : '<option value="">—</option>';
        version.disabled = !versions.length;
      };
      const syncApps = () => {
        const managed = MANAGED.includes(engine.value);
        const items = S.data.apps.filter((item) => item.spec.username === username.value
          && item.spec.runtime.engine === engine.value);
        app.innerHTML = managed
          ? (items.length
            ? items.map((item) => `<option value="${esc(item.spec.name)}">${esc(item.spec.name)} · ${esc(item.spec.port)}</option>`).join('')
            : '<option value="">— sin aplicaciones compatibles —</option>')
          : '<option value="">— no aplica —</option>';
        app.disabled = !managed || !items.length;
      };

      const assignments = new Map((S.data.accountPackages || []).map((item) => [item.account, item]));
      const applyAccountBackend = () => {
        const assignment = assignments.get(username.value);
        if (assignment && RUNTIMES[assignment.web_backend]) {
          engine.value = assignment.web_backend;
        }
        syncVersions();
        syncApps();
      };

      engine.addEventListener('change', () => { syncVersions(); syncApps(); });
      username.addEventListener('change', applyAccountBackend);

      if (editing) {
        form.elements.domain.readOnly = true;
        syncVersions();
        syncApps();
        version.value = spec.runtime.version || version.value;
        app.value = spec.app || '';
      } else {
        applyAccountBackend();
      }
    },
    onSubmit: async (form) => {
      const engine = val(form, 'engine');
      const version = val(form, 'version');
      const runtime = (engine === 'static' || engine === 'go')
        ? { engine }
        : { engine, version };
      const managed = MANAGED.includes(engine);
      const app = managed ? val(form, 'app') : null;
      if (managed && !app) throw new Error('Selecciona una aplicación compatible o créala antes');
      const domain = toAsciiDomain(val(form, 'domain'));

      const result = await api('/api/v1/websites', {
        method: 'POST',
        body: {
          domain,
          username: val(form, 'username'),
          aliases: val(form, 'aliases').split(',').map((a) => toAsciiDomain(a)).filter(Boolean),
          runtime,
          app,
          docroot: val(form, 'docroot'),
          tls: val(form, 'tls'),
          force_https: bool(form, 'force_https'),
          enabled: bool(form, 'enabled'),
          locale: window.RYNX_I18N ? window.RYNX_I18N.getLanguage() : 'en',
        },
      });
      toast(editing ? T('Sitio actualizado') : 'Sitio publicado');
      if (result.cert_job) {
        showCertJob(result.cert_job, domain, { email: S.user.email }).catch(() => {});
      }
      await refresh();
    },
  });
}

/* ---------------- files ---------------- */

function fileJoin(directory, name) {
  return directory ? `${directory}/${name}` : name;
}

function base64ToBytes(value) {
  const binary = atob(value || '');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || '').split(',', 2)[1] || '');
    reader.onerror = () => reject(reader.error || new Error('No se pudo leer el archivo'));
    reader.readAsDataURL(file);
  });
}

const FILE_UPLOAD_LIMIT = 5 * 1024 * 1024;

async function uploadOneFile(file, targetPath) {
  if (file.size > FILE_UPLOAD_LIMIT) {
    throw new Error(TF('{name}: supera 5 MB', { name: file.name }));
  }
  const data = await fileToBase64(file);
  await api('/api/v1/files/upload', {
    method: 'POST',
    body: {
      domain: S.files.domain,
      path: targetPath,
      name: file.name,
      data,
    },
  });
}

function readDirectoryEntries(reader) {
  return new Promise((resolve, reject) => {
    const entries = [];
    const read = () => {
      reader.readEntries((batch) => {
        if (!batch.length) {
          resolve(entries);
          return;
        }
        entries.push(...batch);
        read();
      }, reject);
    };
    read();
  });
}

async function uploadDroppedEntry(entry, targetPath, stats) {
  if (entry.isFile) {
    try {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      await uploadOneFile(file, targetPath);
      stats.files += 1;
    } catch (err) {
      stats.failed += 1;
      stats.lastError = err.message;
    }
    return;
  }
  if (!entry.isDirectory) return;
  let childPath = targetPath;
  try {
    await api('/api/v1/files/mkdir', {
      method: 'POST',
      body: { domain: S.files.domain, path: targetPath, name: entry.name },
    });
    stats.directories += 1;
    childPath = fileJoin(targetPath, entry.name);
  } catch (err) {
    childPath = fileJoin(targetPath, entry.name);
  }
  const children = await readDirectoryEntries(entry.createReader());
  for (const child of children) {
    await uploadDroppedEntry(child, childPath, stats);
  }
}

async function uploadDroppedItems(items) {
  const entries = [];
  const files = [];
  for (const item of items) {
    const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
    if (entry) entries.push(entry);
    else {
      const file = typeof item.getAsFile === 'function' ? item.getAsFile() : null;
      if (file) files.push(file);
    }
  }
  if (!entries.length && !files.length) return;
  const stats = { files: 0, directories: 0, failed: 0, lastError: '' };
  const status = $('#file-upload-status');
  if (status) {
    status.hidden = false;
    status.textContent = T('Subiendo…');
  }
  for (const file of files) {
    try {
      await uploadOneFile(file, S.files.path);
      stats.files += 1;
    } catch (err) {
      stats.failed += 1;
      stats.lastError = err.message;
    }
  }
  for (const entry of entries) {
    await uploadDroppedEntry(entry, S.files.path, stats);
    if (status) {
      status.textContent = TF('Subiendo: {files} archivo(s), {directories} carpeta(s)…', stats);
    }
  }
  if (stats.failed) {
    toast(uploadSummary(stats), 'error');
  } else {
    toast(uploadSummary(stats));
  }
  await navigate('files');
}

async function uploadFileList(files, targetPath, stats) {
  const created = new Set();
  for (const file of files) {
    const relative = file.webkitRelativePath || file.name;
    const parts = relative.split('/').filter(Boolean);
    parts.pop();
    let dirPath = targetPath;
    for (const part of parts) {
      const parent = dirPath;
      dirPath = fileJoin(dirPath, part);
      if (!created.has(dirPath)) {
        try {
          await api('/api/v1/files/mkdir', {
            method: 'POST',
            body: { domain: S.files.domain, path: parent, name: part },
          });
          stats.directories += 1;
        } catch (err) {
          // The folder may already exist; continue with the files inside it.
        }
        created.add(dirPath);
      }
    }
    try {
      await uploadOneFile(file, dirPath);
      stats.files += 1;
    } catch (err) {
      stats.failed += 1;
      stats.lastError = err.message;
    }
  }
}

function uploadSummary(stats) {
  if (stats.failed) {
    return TF('Archivos subidos: {files}. Errores: {failed}. Último error: {lastError}', stats);
  }
  return TF('Archivos subidos: {files}. Carpetas subidas: {directories}.', stats);
}

async function runUpload(files, targetPath) {
  const stats = { files: 0, directories: 0, failed: 0, lastError: '' };
  const status = $('#file-upload-status');
  if (status) {
    status.hidden = false;
    status.textContent = T('Subiendo…');
  }
  await uploadFileList(files, targetPath, stats);
  toast(uploadSummary(stats), stats.failed ? 'error' : 'ok');
  await navigate('files');
}

function fileBreadcrumb(path) {
  const parts = String(path || '').split('/').filter(Boolean);
  let html = `<button class="crumb" data-action="file-open" data-id="">${esc(T('Raíz'))}</button>`;
  let current = '';
  for (const part of parts) {
    current = current ? `${current}/${part}` : part;
    html += ` <span class="muted">/</span> <button class="crumb" data-action="file-open" data-id="${esc(current)}">${esc(part)}</button>`;
  }
  return `<div class="breadcrumb">${html}</div>`;
}

function fileKind(kind) {
  return { dir: 'Carpeta', file: 'Archivo', symlink: 'Enlace', other: 'Otro' }[kind] || kind;
}

function fileQuery(path) {
  return `/api/v1/files?domain=${encodeURIComponent(S.files.domain)}&path=${encodeURIComponent(path || '')}`;
}

async function renderFiles() {
  await loadList('websites');
  const sites = S.data.websites || [];
  if (!sites.length) {
    $('#view').innerHTML = sectionHead('Archivos') +
      `<div class="card empty"><strong>${esc(T('No hay sitios web'))}</strong><span>${esc(T('Crea un sitio web para gestionar sus archivos.'))}</span></div>`;
    return;
  }
  if (!S.files.domain || !sites.some((site) => site.spec.domain === S.files.domain)) {
    S.files.domain = sites[0].spec.domain;
    S.files.path = '';
  }

  let data;
  try {
    data = await api(fileQuery(S.files.path));
  } catch (err) {
    $('#view').innerHTML = sectionHead('Archivos') +
      `<div class="card empty"><strong>${esc(T('No se pudo abrir el gestor'))}</strong><span>${esc(err.message)}</span></div>`;
    return;
  }
  S.files.entries = data.entries || [];
  S.files.path = data.path || '';

  const write = canWrite();
  const siteLabel = `<span class="chip">${esc(S.files.domain)}</span>`;
  const actions = [
    write ? `<button class="btn primary" data-action="file-new-folder">${esc(T('Nueva carpeta'))}</button>` : '',
    write ? `<label class="btn ghost">${esc(T('Subir archivo'))}<input type="file" id="file-upload" hidden multiple></label>` : '',
    write ? `<label class="btn ghost">${esc(T('Subir carpeta'))}<input type="file" id="folder-upload" webkitdirectory multiple hidden></label>` : '',
    `<button class="btn ghost" data-action="files-refresh">${esc(T('Actualizar'))}</button>`,
  ].filter(Boolean).join('');

  const rows = S.files.entries.map((entry) => {
    const path = fileJoin(S.files.path, entry.name);
    const rowActions = [];
    if (entry.kind === 'dir') rowActions.push(btn(T('Abrir'), 'file-open', path));
    if (entry.kind === 'file') {
      rowActions.push(btn(T('Editar'), 'file-edit', path));
      rowActions.push(btn(T('Descargar'), 'file-download', path));
    }
    if (write) {
      rowActions.push(btn(T('Renombrar'), 'file-rename', path));
      rowActions.push(btn(T('Eliminar'), 'file-delete', path, 'tiny danger'));
    }
    return [
      td(`<div class="cell-title">${esc(entry.name)}</div>`),
      td(esc(T(fileKind(entry.kind)))),
      td(entry.kind === 'file' ? esc(fmtBytes(entry.size)) : '<span class="muted">—</span>'),
      td(entry.modified ? esc(fmtDate(entry.modified)) : '<span class="muted">—</span>'),
      td(rowActions.join(''), 'actions'),
    ];
  });

  const dropHint = write
    ? `<div class="file-drop-hint">${esc(T('Arrastra archivos o carpetas aquí para subirlos'))}</div>`
    : '';
  $('#view').innerHTML =
    sectionHead('Archivos', actions) +
    `<div class="file-toolbar">${siteLabel}${fileBreadcrumb(S.files.path)}</div>` +
    `<div class="file-drop" id="file-drop">${dropHint}<div class="file-upload-status" id="file-upload-status" hidden></div>` +
    table(['Nombre', 'Tipo', 'Tamaño', 'Modificado', ''], rows, 'Esta carpeta está vacía.') +
    '</div>';

  const upload = $('#file-upload');
  if (upload) {
    upload.addEventListener('change', async () => {
      const files = Array.from(upload.files || []);
      upload.value = '';
      if (!files.length) return;
      await runUpload(files, S.files.path);
    });
  }
  const folderUpload = $('#folder-upload');
  if (folderUpload) {
    folderUpload.addEventListener('change', async () => {
      const files = Array.from(folderUpload.files || []);
      folderUpload.value = '';
      if (!files.length) return;
      await runUpload(files, S.files.path);
    });
  }
  const dropZone = $('#file-drop');
  if (write && dropZone) {
    const highlight = () => dropZone.classList.add('dragover');
    const clear = () => dropZone.classList.remove('dragover');
    dropZone.addEventListener('dragenter', (event) => {
      if (!event.dataTransfer || !Array.from(event.dataTransfer.types || []).includes('Files')) return;
      event.preventDefault();
      highlight();
    });
    dropZone.addEventListener('dragover', (event) => {
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
      highlight();
    });
    dropZone.addEventListener('dragleave', (event) => {
      if (!dropZone.contains(event.relatedTarget)) clear();
    });
    dropZone.addEventListener('drop', async (event) => {
      event.preventDefault();
      clear();
      const items = Array.from(event.dataTransfer?.items || []);
      await uploadDroppedItems(items);
    });
  }
}

async function openFileEditor(path) {
  const data = await api(`/api/v1/files/read?domain=${encodeURIComponent(S.files.domain)}&path=${encodeURIComponent(path)}`);
  const bytes = base64ToBytes(data.data);
  if (bytes.length > 1024 * 1024) {
    toast('El archivo es demasiado grande para editarlo; descárgalo', 'error');
    return;
  }
  if (bytes.includes(0)) {
    toast('El archivo parece binario; descárgalo para editarlo', 'error');
    return;
  }
  const text = new TextDecoder().decode(bytes);
  openModal({
    title: T('Editar') + ' · ' + path,
    submitLabel: 'Guardar',
    html: `<div class="stack">${field('content', 'Contenido', `<textarea name="content" class="file-editor">${esc(text)}</textarea>`, '', true)}</div>`,
    onSubmit: async (form) => {
      const content = form.elements.content.value;
      await api('/api/v1/files/write', {
        method: 'PUT',
        body: {
          domain: S.files.domain,
          path,
          data: bytesToBase64(new TextEncoder().encode(content)),
        },
      });
      toast('Archivo guardado');
      await navigate('files');
    },
  });
}

async function downloadFile(path) {
  const data = await api(`/api/v1/files/read?domain=${encodeURIComponent(S.files.domain)}&path=${encodeURIComponent(path)}`);
  const bytes = base64ToBytes(data.data);
  const blob = new Blob([bytes]);
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = path.split('/').pop() || 'archivo';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function openNewFolderModal() {
  openModal({
    title: 'Nueva carpeta',
    submitLabel: 'Crear',
    html: `<div class="stack">${fInput('name', 'Nombre', { required: true, placeholder: 'assets' })}</div>`,
    onSubmit: async (form) => {
      await api('/api/v1/files/mkdir', {
        method: 'POST',
        body: { domain: S.files.domain, path: S.files.path, name: val(form, 'name') },
      });
      toast('Carpeta creada');
      await navigate('files');
    },
  });
}

async function renameFile(path) {
  const current = path.split('/').pop() || '';
  const name = prompt('Nuevo nombre', current);
  if (!name || name === current) return;
  await api('/api/v1/files/rename', {
    method: 'POST',
    body: { domain: S.files.domain, path, new_name: name },
  });
  toast('Archivo renombrado');
  await navigate('files');
}

async function deleteFile(path) {
  const entry = (S.files.entries || []).find((item) => fileJoin(S.files.path, item.name) === path);
  const isDir = entry && entry.kind === 'dir';
  const question = isDir
    ? TF('¿Eliminar la carpeta {path} y todo su contenido?', { path })
    : TF('¿Eliminar el archivo {path}?', { path });
  if (!confirm(question)) return;
  await api(
    `/api/v1/files?domain=${encodeURIComponent(S.files.domain)}&path=${encodeURIComponent(path)}&recursive=${isDir ? 'true' : 'false'}`,
    { method: 'DELETE' },
  );
  toast('Eliminado');
  await navigate('files');
}

/* ---------------- mail ---------------- */

function mailDomainByDomain(domain) {
  return (S.data.mailDomains || []).find((mail) => mail.domain === domain);
}

function mailAccountById(id) {
  return (S.data.mailAccounts || []).find((account) => account.id === id);
}

function mailList(value, domain) {
  return String(value || '')
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => toAsciiEmail(item.includes('@') ? item : `${item}@${domain}`));
}

async function renderMail() {
  await Promise.all([
    loadList('mailDomains'),
    loadList('mailAccounts'),
    loadList('websites'),
    loadList('accounts'),
  ]);
  const writable = canWrite();
  const rows = (S.data.websites || []).map((site) => {
    const spec = site.spec;
    const mail = mailDomainByDomain(spec.domain);
    const accounts = (S.data.mailAccounts || []).filter((account) => account.domain === spec.domain);
    if (!mail) {
      return [
        td(`<div class="cell-title">${esc(spec.domain)}</div><div class="cell-sub">${esc(spec.username)}</div>`),
        td('<span class="muted">-</span>'),
        td('<span class="muted">-</span>'),
        td(badge('sin correo', '')),
        td('0'),
        td(writable ? btn('Activar correo', 'mail-enable', spec.domain, 'tiny primary') : ''),
      ];
    }
    const actions = [
      writable ? btn('Cuenta', 'mail-account-new', spec.domain, 'tiny primary') : '',
      writable ? btn(mail.enabled ? 'Desactivar' : 'Activar', 'mail-toggle', spec.domain, 'tiny ghost') : '',
      writable ? btn('SSL', 'mail-tls', spec.domain, 'tiny ghost') : '',
      writable ? btn('Catch-all', 'mail-catchall', spec.domain, 'tiny ghost') : '',
      writable ? btn('Eliminar', 'mail-delete', spec.domain, 'tiny danger') : '',
    ].filter(Boolean).join(' ');
    return [
      td(`<div class="cell-title">${esc(mail.domain)}</div><div class="cell-sub">${esc(mail.username)}</div>`),
      td(`<span class="mono small">mail.${esc(mail.domain)}</span>`),
      td(`<a class="mono small" href="${esc(mail.webmail_url)}" target="_blank" rel="noopener">webmail.${esc(mail.domain)}</a>`),
      td(certBadge(mail.tls_status)),
      td(String(accounts.length)),
      td(`${mail.enabled ? badge('activo', 'ok') : badge('desactivado', 'warn')} ${actions}`),
    ];
  });
  const accountRows = (S.data.mailAccounts || []).map((account) => [
    td(`<div class="cell-title">${esc(account.address)}</div><div class="cell-sub">${esc(account.domain)}</div>`),
    td(`${esc(account.quota_mb)} MB`),
    td(`<div class="mono small">${esc((account.aliases || []).join(', ') || '-')}</div><div class="cell-sub">${esc((account.forward_to || []).join(', ') || '')}</div>`),
    td(account.enabled ? badge('activo', 'ok') : badge('deshabilitado', 'warn')),
    td(writable ? [
      btn('Contraseña', 'mail-account-passwd', account.id, 'tiny'),
      btn(account.enabled ? 'Desactivar' : 'Activar', 'mail-account-toggle', account.id, 'tiny ghost'),
      btn('Eliminar', 'mail-account-delete', account.id, 'tiny danger'),
    ].join(' ') : ''),
  ]);
  $('#view').innerHTML = `
    <div class="card"><p class="muted small" style="margin:0">
      Cada dominio usa <span class="mono">mail.dominio</span> para IMAP/SMTP y
      <span class="mono">webmail.dominio</span> para Roundcube. La autorespuesta y los filtros
      se gestionan dentro del webmail con el plugin Managesieve.
    </p></div>
    ${sectionHead('Dominios de correo', writable ? '<button class="btn primary" data-action="mail-new">Activar correo</button>' : '')}
    ${table(['Dominio', 'Servidor', 'Webmail', 'TLS', 'Buzones', 'Acciones'], rows, 'Publica un sitio para poder activar su correo.')}
    ${sectionHead('Buzones', '')}
    ${table(['Buzón', 'Cuota', 'Alias / reenvío', 'Estado', 'Acciones'], accountRows, 'Sin buzones; activa el correo de un dominio y crea el primero.')}`;
}

function openMailEnableModal() {
  const candidates = (S.data.websites || []).filter((site) => !mailDomainByDomain(site.spec.domain));
  if (!candidates.length) {
    toast('Todos los sitios ya tienen correo activado', 'error');
    return;
  }
  openModal({
    title: 'Activar correo',
    submitLabel: 'Activar',
    html: `<div class="form-grid">
      ${fSelect('domain', 'Sitio', candidates.map((site) => ({ value: site.spec.domain, label: site.spec.domain })), { required: true })}
      <p class="hint full">Se crea <span class="mono">mail.dominio</span>, <span class="mono">webmail.dominio</span> y los registros MX, SPF, DKIM, DMARC, SRV y TLS-RPT.</p>
    </div>`,
    onSubmit: async (form) => {
      const domain = val(form, 'domain');
      const site = candidates.find((item) => item.spec.domain === domain);
      if (!site) throw new Error('Sitio no encontrado');
      const result = await api('/api/v1/mail/domains', {
        method: 'POST',
        body: { domain, username: site.spec.username, enabled: true, catch_all: null },
      });
      toast('Correo activado');
      if (result.cert_job) {
        showCertJob(result.cert_job, `webmail.${domain}`, {
          email: S.user.email,
          siteCreated: false,
        }).catch(() => {});
      }
      await refresh();
    },
  });
}

async function enableMail(domain) {
  const site = (S.data.websites || []).find((item) => item.spec.domain === domain);
  if (!site) throw new Error('Sitio no encontrado');
  const result = await api('/api/v1/mail/domains', {
    method: 'POST',
    body: { domain, username: site.spec.username, enabled: true, catch_all: null },
  });
  toast('Correo activado');
  if (result.cert_job) {
    showCertJob(result.cert_job, `webmail.${domain}`, {
      email: S.user.email,
      siteCreated: false,
    }).catch(() => {});
  }
  await refresh();
}

async function toggleMailDomain(domain) {
  const mail = mailDomainByDomain(domain);
  if (!mail) return;
  const enabled = !mail.enabled;
  const result = await api('/api/v1/mail/domains', {
    method: 'POST',
    body: {
      domain: mail.domain,
      username: mail.username,
      enabled,
      catch_all: mail.catch_all,
    },
  });
  toast(enabled ? 'Correo activado' : 'Correo desactivado');
  if (enabled && result.cert_job) {
    showCertJob(result.cert_job, `webmail.${domain}`, {
      email: S.user.email,
      siteCreated: false,
    }).catch(() => {});
  }
  await refresh();
}

function openMailAccountModal(domain) {
  openModal({
    title: T('Nuevo buzón') + ' · ' + domain,
    submitLabel: 'Crear buzón',
    html: `<div class="form-grid">
      ${fInput('local_part', 'Buzón', { required: true, placeholder: 'info', help: 'se usará como info@dominio' })}
      ${fInput('password', 'Contraseña', { type: 'password', required: true, autocomplete: 'new-password', help: 'mínimo 12 caracteres y 3 clases' })}
      ${fInput('quota_mb', 'Cuota (MB)', { type: 'number', value: 1024, min: 64, required: true })}
      ${fInput('aliases', 'Alias locales', { placeholder: 'ventas, soporte', help: 'separados por coma; se añade @dominio' })}
      ${fInput('forward_to', 'Reenviar a', { placeholder: 'otro@example.com', help: 'opcional; conserva copia local' })}
      <div class="full">${fCheck('enabled', 'Buzón activo', true)}</div>
    </div>`,
    onSubmit: async (form) => {
      await api('/api/v1/mail/accounts', {
        method: 'POST',
        body: {
          domain,
          local_part: val(form, 'local_part').toLowerCase(),
          password: val(form, 'password'),
          quota_mb: num(form, 'quota_mb', 1024),
          enabled: bool(form, 'enabled'),
          aliases: mailList(val(form, 'aliases'), domain),
          forward_to: mailList(val(form, 'forward_to'), domain),
        },
      });
      toast('Buzón creado');
      await refresh();
    },
  });
}

function openMailPasswordModal(account) {
  if (!account) return;
  openModal({
    title: T('Contraseña') + ' · ' + account.address,
    submitLabel: 'Actualizar',
    html: `<div class="stack">${fInput('password', 'Nueva contraseña', { type: 'password', required: true, autocomplete: 'new-password', help: 'mínimo 12 caracteres y 3 clases' })}</div>`,
    onSubmit: async (form) => {
      await api('/api/v1/mail/accounts', {
        method: 'POST',
        body: {
          id: account.id,
          domain: account.domain,
          local_part: account.local_part,
          password: val(form, 'password'),
          quota_mb: account.quota_mb,
          enabled: account.enabled,
          aliases: account.aliases,
          forward_to: account.forward_to,
        },
      });
      toast('Contraseña actualizada');
    },
  });
}

function openMailCatchAllModal(domain) {
  const mail = mailDomainByDomain(domain);
  if (!mail) return;
  openModal({
    title: T('Catch-all') + ' · ' + domain,
    submitLabel: 'Guardar',
    html: `<div class="stack">${fInput('catch_all', 'Destino', { type: 'email', value: mail.catch_all || '', placeholder: 'buzon@dominio', help: 'vacío para desactivar el catch-all' })}</div>`,
    onSubmit: async (form) => {
      await api('/api/v1/mail/domains', {
        method: 'POST',
        body: {
          domain: mail.domain,
          username: mail.username,
          enabled: mail.enabled,
          catch_all: val(form, 'catch_all') ? toAsciiEmail(val(form, 'catch_all')) : null,
        },
      });
      toast('Catch-all actualizado');
      await refresh();
    },
  });
}

async function toggleMailAccount(account) {
  if (!account) return;
  await api('/api/v1/mail/accounts', {
    method: 'POST',
    body: {
      id: account.id,
      domain: account.domain,
      local_part: account.local_part,
      quota_mb: account.quota_mb,
      enabled: !account.enabled,
      aliases: account.aliases,
      forward_to: account.forward_to,
    },
  });
  toast(account.enabled ? 'Buzón desactivado' : 'Buzón activado');
  await refresh();
}

async function retryMailTls(domain) {
  const result = await api(`/api/v1/mail/domains/${encodeURIComponent(domain)}/tls`, {
    method: 'POST',
  });
  if (result.cert_job) {
    showCertJob(result.cert_job, `webmail.${domain}`, {
      email: S.user.email,
      siteCreated: false,
    }).catch(() => {});
  }
  await refresh();
}

/* ---------------- applications ---------------- */

async function renderApps() {
  await Promise.all([loadList('apps'), loadList('accounts')]);
  const writable = canWrite();
  const rows = S.data.apps.map((app) => {
    const spec = app.spec;
    return [
      td(`<div class="cell-title">${esc(spec.name)}</div><div class="cell-sub">${esc(spec.username)}</div>`),
      td(`<span class="chip">${esc(runtimeLabel(spec.runtime))}</span>`),
      td(`<span class="mono">127.0.0.1:${esc(spec.port)}</span>`),
      td(`<span class="mono small">${esc(spec.command)} ${esc((spec.args || []).join(' '))}</span>`),
      td(spec.enabled ? badge('activa', 'ok') : badge('detenida', 'warn')),
      td(writable ? btn('Eliminar', 'app-delete', `${spec.username}/${spec.name}`, 'tiny danger') : '', 'actions'),
    ];
  });

  $('#view').innerHTML =
    sectionHead('Aplicaciones gestionadas', writable ? `<button class="btn primary" data-action="app-new">Nueva aplicación</button>` : '') +
    table(['Aplicación', 'Runtime', 'Escucha', 'Comando', 'Estado', ''], rows, 'Node, Python, Ruby, Java, .NET y Go se ejecutan bajo systemd.');
}

const INSTALLER_STATUS_LABELS = {
  running: 'En cola',
  'creating website': 'Creando el sitio',
  'creating database': 'Creando la base de datos',
  downloading: 'Descargando WordPress',
  installing: 'Instalando la aplicación',
  succeeded: 'Completado',
  failed: 'Error',
};

async function renderInstaller() {
  const [, versionsData] = await Promise.all([
    loadList('accounts'),
    api('/api/v1/php/versions'),
  ]);
  S.phpVersions = versionsData.versions || [];
  const writable = canWrite();
  const apps = [
    {
      app: 'wordpress',
      title: 'WordPress',
      text: 'Blog o CMS con base de datos, wp-config, sales y cuenta de administrador.',
    },
    {
      app: 'laravel',
      title: 'Laravel',
      text: 'Framework PHP instalado con Composer, .env y document root en public/. No crea usuario administrador ni panel; define tus rutas o instala un starter kit.',
    },
  ];
  const cards = apps
    .map(
      (item) => `<div class="card">
        <div class="cell-title">${esc(item.title)}</div>
        <p class="muted small">${esc(item.text)}</p>
        <p class="muted small">Crea un sitio nuevo con PHP-FPM, base de datos y certificado TLS.</p>
        ${writable ? `<button class="btn primary" data-action="installer-new" data-id="${item.app}">${esc(TF('Instalar {app}', { app: item.title }))}</button>` : ''}
      </div>`,
    )
    .join('');
  $('#view').innerHTML =
    sectionHead('Instalador de aplicaciones') +
    `<div class="grid cols-2">${cards}</div>` +
    `<div class="card"><p class="muted small" style="margin:0">El instalador crea el sitio, el pool PHP, la base de datos
    y los archivos de la aplicación. No sobrescribe sitios existentes y requiere una cuenta de hosting.</p></div>`;
}

function openInstallerModal(app) {
  if (!S.data.accounts.length) {
    toast('Primero crea una cuenta de hosting', 'error');
    return;
  }
  const wordpress = app === 'wordpress';
  const versions = (S.phpVersions && S.phpVersions.length ? S.phpVersions : ['8.5']).map((version) => ({
    value: version,
    label: version,
  }));
  openModal({
    title: wordpress ? T('Instalar WordPress') : T('Instalar Laravel'),
    submitLabel: 'Instalar',
    html: `<div class="form-grid">
      ${fSelect('username', 'Cuenta', accountOptions(false), { required: true })}
      ${fInput('domain', 'Dominio', { required: true, placeholder: 'blog.example.com' })}
      ${fSelect('php_version', 'PHP-FPM', versions, { value: versions[0]?.value })}
      ${fInput('title', wordpress ? 'Título del sitio' : 'Nombre de la aplicación', { value: '' })}
      ${wordpress ? fInput('admin_user', 'Usuario administrador', { value: 'admin' }) : ''}
      ${wordpress ? fInput('admin_email', 'Email administrador', { type: 'email', value: S.user.email || '' }) : ''}
      ${wordpress ? fInput('admin_password', 'Contraseña administrador', { type: 'password', help: 'déjala vacía para generar una segura' }) : ''}
      <div class="full">${fCheck('tls', 'Solicitar certificado Let\'s Encrypt', true)}</div>
    </div>`,
    onSubmit: async (form) => {
      const body = {
        username: form.elements.username.value,
        domain: form.elements.domain.value,
        app,
        php_version: form.elements.php_version.value,
        title: form.elements.title.value,
        admin_user: wordpress ? form.elements.admin_user.value : '',
        admin_email: wordpress ? form.elements.admin_email.value : '',
        admin_password: wordpress ? form.elements.admin_password.value : '',
        tls: form.elements.tls.checked,
      };
      const job = await api('/api/v1/installer/install', { method: 'POST', body });
      const status = document.createElement('p');
      status.className = 'muted small';
      form.querySelector('.modal-actions').before(status);
      let current = job;
      while (current && current.status !== 'succeeded' && current.status !== 'failed') {
        status.textContent = T(INSTALLER_STATUS_LABELS[current.status] || current.status);
        await new Promise((resolve) => setTimeout(resolve, 2000));
        current = await api(`/api/v1/installer/jobs/${encodeURIComponent(current.id)}`);
      }
      if (!current || current.status !== 'succeeded') {
        throw new Error(current ? current.message : T('La instalación falló'));
      }
      const lines = [
        `${T('Sitio')}: ${current.url}`,
        current.database ? `${T('Base de datos')}: ${current.database}` : '',
        current.db_user ? `${T('Usuario')}: ${current.db_user}` : '',
        current.db_password ? `${T('Contraseña')}: ${current.db_password}` : '',
        current.db_host ? `${T('Servidor')}: ${current.db_host}` : '',
        current.admin_user ? `${T('Usuario administrador')}: ${current.admin_user}` : '',
        current.admin_password ? `${T('Contraseña administrador')}: ${current.admin_password}` : '',
        '',
        T('Guarda estas credenciales ahora.'),
      ].filter(Boolean);
      showOutput(T('Aplicación instalada'), lines.join('\n'));
      await refresh();
    },
  });
}

function openAppModal() {
  if (!S.data.accounts.length) {
    toast('Primero crea una cuenta de hosting', 'error');
    return;
  }
  const engineOptions = MANAGED.map((engine) => ({ value: engine, label: RUNTIMES[engine].label }));

  openModal({
    title: 'Nueva aplicación',
    submitLabel: 'Crear aplicación',
    html: `<div class="form-grid">
      ${fSelect('username', 'Cuenta', accountOptions(false), { required: true })}
      ${fInput('name', 'Nombre', { required: true, placeholder: 'api', help: 'minúsculas, 2-32 caracteres' })}
      ${fSelect('engine', 'Runtime', engineOptions, { value: 'node' })}
      ${fSelect('version', 'Versión', RUNTIMES.node.versions.map((v) => ({ value: v, label: v })), { value: '22' })}
      ${fInput('port', 'Puerto interno', { type: 'number', value: 4100, min: 1024, max: 65535, required: true, help: 'solo loopback; Nginx hará proxy' })}
      ${fInput('entrypoint', 'Entrypoint', { value: 'server.js', required: true, help: 'archivo o artefacto relativo a la app' })}
      ${fInput('command', 'Comando', { value: 'node', required: true, list: 'app-commands', help: 'ejecutable permitido para el runtime' })}
      <datalist id="app-commands">
        <option value="node"></option>
        <option value="gunicorn"></option>
        <option value="uvicorn"></option>
        <option value="python3"></option>
        <option value="puma"></option>
        <option value="bundle"></option>
        <option value="ruby"></option>
        <option value="java"></option>
        <option value="dotnet"></option>
      </datalist>
      ${fInput('args', 'Argumentos', { placeholder: 'server.js', help: 'separados por coma' })}
      ${fTextarea('env', 'Variables de entorno', { placeholder: 'NODE_ENV=production\nAPP_KEY=...', help: 'una KEY=VALUE por línea', full: true })}
      <div class="full">${fCheck('enabled', 'Arrancar aplicación', true)}</div>
    </div>`,
    onMount: (form) => {
      const engine = form.elements.engine;
      const version = form.elements.version;
      const entrypoint = form.elements.entrypoint;
      const command = form.elements.command;
      const args = form.elements.args;
      const port = form.elements.port;

      const sync = () => {
        const meta = RUNTIMES[engine.value] || { versions: [], commands: [] };
        version.innerHTML = meta.versions.length
          ? meta.versions.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join('')
          : '<option value="">—</option>';
        version.disabled = !meta.versions.length;
        if (meta.commands.length) command.value = meta.commands[0];
        if (meta.entry) entrypoint.value = meta.entry;
        if (meta.exampleArgs !== undefined) {
          args.value = meta.exampleArgs.replaceAll('4100', String(port.value || 4100));
        }
      };
      engine.addEventListener('change', sync);
      port.addEventListener('input', () => {
        const meta = RUNTIMES[engine.value];
        if (meta && meta.exampleArgs) {
          args.value = meta.exampleArgs.replaceAll('4100', String(port.value || 4100));
        }
      });
      sync();
    },
    onSubmit: async (form) => {
      const engine = val(form, 'engine');
      const version = val(form, 'version');
      const runtime = (engine === 'go') ? { engine } : { engine, version };
      const env = {};
      for (const line of val(form, 'env').split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const index = trimmed.indexOf('=');
        if (index <= 0) throw new Error(TF('Variable de entorno inválida: {value}', { value: trimmed }));
        env[trimmed.slice(0, index).trim()] = trimmed.slice(index + 1);
      }
      await api('/api/v1/apps', {
        method: 'POST',
        body: {
          username: val(form, 'username'),
          name: val(form, 'name').toLowerCase(),
          runtime,
          port: num(form, 'port', 4100),
          entrypoint: val(form, 'entrypoint'),
          command: val(form, 'command'),
          args: val(form, 'args').split(',').map((a) => a.trim()).filter(Boolean),
          env,
          enabled: bool(form, 'enabled'),
        },
      });
      toast('Aplicación creada');
      await refresh();
    },
  });
}

/* ---------------- php ---------------- */

async function renderPhp() {
  await Promise.all([loadList('pools'), loadList('accounts')]);
  const writable = canWrite();
  const rows = S.data.pools.map((pool) => {
    const spec = pool.spec;
    return [
      td(`<div class="cell-title">${esc(spec.username)}</div>`),
      td(`<span class="chip">PHP ${esc(spec.version)}</span>`),
      td(esc(spec.process_manager)),
      td(esc(spec.max_children)),
      td(`${esc(spec.memory_limit_mb)} MB`),
      td(`<span class="mono small">${esc(pool.socket)}</span>`),
      td(statusBadge(spec.enabled)),
      td(writable ? btn('Eliminar', 'php-delete', spec.username, 'tiny danger') : '', 'actions'),
    ];
  });

  $('#view').innerHTML =
    sectionHead('Pools PHP-FPM', writable ? `<button class="btn primary" data-action="php-new">Nuevo pool</button>` : '') +
    table(['Cuenta', 'Versión', 'PM', 'Workers', 'Memoria', 'Socket', 'Estado', ''], rows, 'No hay pools; se crean automáticamente al publicar un sitio PHP.');
}

async function openPhpModal() {
  if (!S.data.accounts.length) {
    toast('Primero crea una cuenta de hosting', 'error');
    return;
  }
  const phpVersions = await loadPhpVersions();
  openModal({
    title: 'Nuevo pool PHP-FPM',
    submitLabel: 'Crear pool',
    html: `<div class="form-grid">
      ${fSelect('username', 'Cuenta', accountOptions(false), { required: true })}
      ${fSelect('version', 'Versión PHP', phpVersions.map((v) => ({ value: v, label: v })), { value: phpVersions[0] || '' })}
      ${fSelect('process_manager', 'Gestor de procesos', [
        { value: 'dynamic', label: 'dynamic' },
        { value: 'ondemand', label: 'ondemand' },
        { value: 'static', label: 'static' },
      ], { value: 'dynamic' })}
      ${fInput('max_children', 'Max children', { type: 'number', value: 8, min: 1, max: 64, required: true })}
      ${fInput('memory_limit_mb', 'Memoria por worker (MB)', { type: 'number', value: 256, min: 16, max: 2048, required: true })}
      ${fInput('upload_max_mb', 'Subida máxima (MB)', { type: 'number', value: 64, min: 1, max: 4096, required: true })}
      <div class="full">${fCheck('enabled', 'Pool activo', true)}</div>
    </div>`,
    onSubmit: async (form) => {
      await api('/api/v1/php-pools', {
        method: 'POST',
        body: {
          username: val(form, 'username'),
          version: val(form, 'version'),
          process_manager: val(form, 'process_manager'),
          max_children: num(form, 'max_children', 8),
          memory_limit_mb: num(form, 'memory_limit_mb', 256),
          upload_max_mb: num(form, 'upload_max_mb', 64),
          enabled: bool(form, 'enabled'),
        },
      });
      toast('Pool PHP actualizado');
      await refresh();
    },
  });
}

/* ---------------- ssl ---------------- */

async function renderSsl() {
  await Promise.all([loadList('certs'), loadList('websites')]);
  const writable = canWrite();
  const scoped = isScoped();
  const sites = new Map((S.data.websites || []).map((site) => [site.spec.domain, site]));
  const rows = S.data.certs.map((cert) => {
    const site = sites.get(cert.domain);
    const canReissue = writable && site && site.spec.tls === 'lets_encrypt';
    return [
      td(`<div class="cell-title">${esc(cert.domain)}</div><div class="cell-sub mono">${esc(cert.path)}</div>`),
      td(esc(cert.issuer || '—')),
      td(esc(fmtDate(cert.not_after))),
      td(certBadge(cert.status)),
      td(canReissue ? btn('Reemitir', 'cert-reissue', cert.domain, 'tiny ghost') : '', 'actions'),
    ];
  });

  const renew = scoped ? '' : '<button class="btn ghost" data-action="cert-renew">Renovar todos</button>';
  const issue = writable ? '<button class="btn primary" data-action="cert-new">Emitir certificado</button>' : '';
  $('#view').innerHTML =
    sectionHead('Certificados TLS', renew + issue) +
    table(['Dominio', 'Emisor', 'Vence', 'Estado', ''], rows, 'No hay certificados; publica un sitio con TLS Let\'s Encrypt.');
}

function openCertModal() {
  const candidates = S.data.websites.filter((w) => w.spec.tls === 'lets_encrypt');
  if (!candidates.length) {
    toast('No hay sitios configurados con Let\'s Encrypt', 'error');
    return;
  }
  openModal({
    title: 'Emitir certificado',
    submitLabel: 'Solicitar',
    html: `<div class="form-grid">
      ${fSelect('domain', 'Sitio', candidates.map((w) => ({ value: w.spec.domain, label: w.spec.domain })), { required: true })}
      ${fInput('email', 'Email de contacto', { type: 'email', value: S.user.email, required: true })}
      <div class="full">${fCheck('staging', 'Usar entorno staging (pruebas)', false)}</div>
      <p class="hint full">El reto HTTP-01 se sirve desde el webroot ACME. Al emitirse, el vhost se re-renderiza con TLS.</p>
    </div>`,
    onSubmit: async (form) => {
      const domain = val(form, 'domain');
      const email = toAsciiEmail(val(form, 'email'));
      const staging = bool(form, 'staging');
      const job = await api('/api/v1/certs/jobs', {
        method: 'POST',
        body: { domain, email, staging },
      });
      await showCertJob(job, domain, { email, staging });
    },
  });
}

function showCertJob(job, domain, options = {}) {
  const root = $('#modal-root');
  const email = options.email || S.user.email || '';
  const staging = Boolean(options.staging);
  const started = Date.now();
  let current = job;
  let closed = false;
  let done = false;
  let pollTimer = null;
  let elapsedTimer = null;
  let resolveDone;
  const finished = new Promise((resolve) => { resolveDone = resolve; });

  root.innerHTML = `
    <div class="modal-backdrop" data-cert-backdrop>
      <div class="modal cert-progress" role="dialog" aria-modal="true">
        <h2>${esc(T('Certificado SSL'))}</h2>
        <p class="muted small mono">${esc(domain)}${staging ? ' · staging' : ''}</p>
        <div class="cert-steps">
          <div class="cert-step done" data-cert-step="site">
            <span class="dot"></span>
            <div><strong>${esc(T(options.siteCreated === false ? 'Sitio' : 'Sitio publicado'))}</strong></div>
          </div>
          <div class="cert-step running" data-cert-step="request">
            <span class="dot"></span>
            <div><strong>${esc(T('Solicitando certificado...'))}</strong><small id="cert-job-message"></small></div>
          </div>
          <div class="cert-step" data-cert-step="https">
            <span class="dot"></span>
            <div><strong>${esc(T('HTTPS activo'))}</strong></div>
          </div>
        </div>
        <div class="cert-progress-meta">
          <span class="muted small">${esc(T('Tiempo transcurrido'))}: <strong id="cert-job-elapsed">0s</strong></span>
          <span class="muted small" id="cert-job-state">${esc(T('Comprobando estado...'))}</span>
        </div>
        <div id="cert-job-result" class="cert-result"></div>
        <p id="cert-job-note" class="hint">${esc(T('El proceso continúa en segundo plano.'))}</p>
        <div class="modal-actions">
          <button type="button" class="btn ghost" data-cert-close>${esc(T('Cerrar'))}</button>
          <button type="button" class="btn primary hidden" data-cert-retry>${esc(T('Reintentar'))}</button>
        </div>
      </div>
    </div>`;

  translateUi(root);

  const setStep = (name, state) => {
    const step = root.querySelector(`[data-cert-step="${name}"]`);
    if (!step) return;
    step.classList.remove('done', 'running', 'failed', 'hidden');
    if (state) step.classList.add(state);
  };

  const finish = () => {
    if (done) return;
    done = true;
    clearTimeout(pollTimer);
    clearInterval(elapsedTimer);
    resolveDone(current);
  };

  const onKey = (event) => {
    if (event.key === 'Escape') close();
  };

  const close = () => {
    if (closed) return;
    closed = true;
    clearTimeout(pollTimer);
    clearInterval(elapsedTimer);
    document.removeEventListener('keydown', onKey);
    if (root.querySelector('.cert-progress')) root.innerHTML = '';
    finish();
  };

  const render = (next) => {
    current = next;
    const message = root.querySelector('#cert-job-message');
    const state = root.querySelector('#cert-job-state');
    const result = root.querySelector('#cert-job-result');
    const retry = root.querySelector('[data-cert-retry]');
    if (!message || !state || !result || !retry) return;
    const note = root.querySelector('#cert-job-note');
    if (next.status === 'succeeded') {
      setStep('request', 'done');
      setStep('https', 'done');
      message.textContent = T('Certificado emitido correctamente');
      state.textContent = T('Certificado emitido correctamente');
      const cert = next.certificate || {};
      const expires = cert.not_after ? fmtDate(cert.not_after) : '-';
      result.innerHTML = `<div class="kv cert-summary">
        <span>${esc(T('Emisor'))}</span><strong>${esc(cert.issuer || '-')}</strong>
        <span>${esc(T('Vence'))}</span><strong>${esc(expires)}</strong>
        <span>${esc(T('Estado'))}</span><span>${certBadge(cert.status || 'active')}</span>
      </div>
      <p class="hint"><a href="https://${esc(domain)}/" target="_blank" rel="noopener">https://${esc(domain)}/</a></p>`;
      if (note) note.classList.add('hidden');
      retry.classList.add('hidden');
      finish();
      toast(T('Certificado emitido correctamente'));
      refresh().catch(() => {});
    } else if (next.status === 'failed') {
      setStep('request', 'failed');
      setStep('https', 'hidden');
      message.textContent = T('No se pudo emitir el certificado');
      state.textContent = T('El sitio se creó, pero HTTPS no está activo.');
      result.innerHTML = `<strong class="cert-failure">${esc(T('No se pudo emitir el certificado'))}</strong>
        <pre class="cert-error">${esc(next.message || '')}</pre>
        <p class="hint">${esc(T('El sitio se creó, pero HTTPS no está activo.'))}</p>`;
      if (note) note.classList.add('hidden');
      retry.classList.remove('hidden');
      finish();
      toast(T('No se pudo emitir el certificado'), 'error');
      refresh().catch(() => {});
    } else {
      setStep('request', 'running');
      setStep('https', '');
      message.textContent = T('Comprobando estado...');
      state.textContent = T('Comprobando estado...');
    }
  };

  const poll = async () => {
    if (closed || done) return;
    try {
      const next = await api(`/api/v1/certs/jobs/${encodeURIComponent(current.id)}`);
      if (closed) return;
      if (!root.querySelector('.cert-progress')) {
        closed = true;
        finish();
        return;
      }
      render(next);
      if (done) return;
    } catch (err) {
      if (closed) return;
      const state = root.querySelector('#cert-job-state');
      if (state) state.textContent = err.message;
    }
    pollTimer = setTimeout(poll, 1500);
  };

  root.querySelector('[data-cert-close]').addEventListener('click', close);
  root.querySelector('[data-cert-backdrop]').addEventListener('click', (event) => {
    if (event.target === event.currentTarget) close();
  });
  root.querySelector('[data-cert-retry]').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const next = await api('/api/v1/certs/jobs', {
        method: 'POST',
        body: { domain, email, staging },
      });
      if (closed) return;
      close();
      await showCertJob(next, domain, { email, staging });
    } catch (err) {
      button.disabled = false;
      toast(err.message, 'error');
    }
  });
  document.addEventListener('keydown', onKey);

  elapsedTimer = setInterval(() => {
    const elapsed = root.querySelector('#cert-job-elapsed');
    if (elapsed) elapsed.textContent = `${Math.floor((Date.now() - started) / 1000)}s`;
  }, 1000);

  render(job);
  poll();
  return finished;
}

/* ---------------- users ---------------- */

async function renderUsers() {
  await loadList('users');
  const rows = S.data.users.map((user) => {
    const self = user.username === S.user.username;
    return [
      td(`<div class="cell-title">${esc(user.username)}</div>${user.account ? `<div class="cell-sub">cuenta: ${esc(user.account)}</div>` : ''}${self ? '<div class="cell-sub">tú</div>' : ''}`),
      td(esc(user.email)),
      td(badge(user.role, user.role === 'owner' ? 'info' : '')),
      td(user.active ? badge('activo', 'ok') : badge('deshabilitado', 'warn')),
      td([
        self ? '' : btn('Entrar', 'impersonate', user.username),
        btn('Contraseña', 'user-passwd', user.username),
        self ? '' : btn(user.active ? 'Desactivar' : 'Activar', 'user-toggle', user.username),
        self ? '' : btn('Eliminar', 'user-delete', user.username, 'tiny danger'),
      ].join(''), 'actions'),
    ];
  });

  $('#view').innerHTML =
    sectionHead('Usuarios del panel', `<button class="btn primary" data-action="user-new">Nuevo usuario</button>`) +
    table(['Usuario', 'Email', 'Rol', 'Estado', ''], rows, 'Solo existe el propietario inicial.');
}

function openUserModal() {
  const roles = isOwner() ? ['owner', 'admin', 'operator', 'viewer'] : ['admin', 'operator', 'viewer'];
  openModal({
    title: 'Nuevo usuario del panel',
    submitLabel: 'Crear usuario',
    html: `<div class="form-grid">
      ${fInput('username', 'Usuario', { required: true, placeholder: 'operador' })}
      ${fInput('email', 'Email', { type: 'email', required: true })}
      ${fInput('password', 'Contraseña', { type: 'password', required: true, autocomplete: 'new-password', help: 'mínimo 12 caracteres, 3 clases' })}
      ${fSelect('role', 'Rol', roles.map((r) => ({ value: r, label: statusLabel(r) })), { value: 'operator' })}
    </div>`,
    onSubmit: async (form) => {
      await api('/api/v1/users', {
        method: 'POST',
        body: {
          username: val(form, 'username').toLowerCase(),
          email: toAsciiEmail(val(form, 'email')),
          password: val(form, 'password'),
          role: val(form, 'role'),
        },
      });
      toast('Usuario creado');
      await refresh();
    },
  });
}

/* ---------------- packages ---------------- */

async function renderPackages() {
  await loadList('packages');
  const rows = S.data.packages.map((pkg) => [
    td(`<div class="cell-title">${esc(pkg.name)}</div>${pkg.is_default ? `<div class="cell-sub">${esc(T('Por defecto'))}</div>` : ''}`),
    td(esc(limitText(pkg.account_mb))),
    td(esc(limitText(pkg.bandwidth_mb))),
    td(esc(pkg.backups)),
    td(esc(limitText(pkg.web_domains))),
    td(esc(limitText(pkg.mail_accounts))),
    td(esc(limitText(pkg.databases))),
    td([
      btn(T('Editar'), 'package-edit', pkg.id),
      pkg.is_default ? '' : btn(T('Eliminar'), 'package-delete', pkg.id, 'tiny danger'),
    ].join(''), 'actions'),
  ]);

  $('#view').innerHTML =
    sectionHead('Paquetes', `<button class="btn primary" data-action="package-new">${T('Nuevo paquete')}</button>`) +
    `<p class="hint" style="margin:0 0 14px">${esc(T('0 significa sin límite. El paquete Por defecto es editable pero no se puede eliminar.'))}</p>` +
    table(
      ['Paquete', 'Cuenta (MB)', 'Ancho de banda', 'Backups', 'Dominios webs - apps', 'Cuentas de email', 'Bases de datos', ''],
      rows,
      'Aún no hay paquetes.',
    );
}

function openPackageModal(pkg = null) {
  const nginxOptions = [
    { value: 'caching', label: 'Caching' },
    { value: 'hosting', label: 'Hosting' },
    { value: 'suspended', label: 'Suspended' },
  ];
  const dnsOptions = [
    { value: 'child-ns', label: 'child-ns' },
    { value: 'no-mail', label: 'No mail' },
    { value: 'gmail', label: 'Gmail' },
    { value: 'office365', label: 'Office 365' },
    { value: 'zoho', label: 'Zoho' },
  ];
  const yesNo = [
    { value: '0', label: 'No' },
    { value: '1', label: 'Sí' },
  ];
  const pick = (field, fallback) => (pkg && pkg[field] !== undefined ? pkg[field] : fallback);

  openModal({
    title: pkg ? T('Editar paquete') + ' · ' + pkg.name : T('Nuevo paquete'),
    submitLabel: pkg ? 'Guardar cambios' : 'Crear paquete',
    html: `<div class="form-grid">
      ${formSection('General', 'Los límites van de 0 a 1000. 0 significa sin límite.')}
      ${fInput('name', 'Nombre del paquete', { required: true, value: pick('name', ''), placeholder: 'Starter' })}
      ${pkgNumber('account_mb', 'Cuenta (MB)', { value: pick('account_mb', 1) })}
      ${pkgNumber('bandwidth_mb', 'Ancho de banda', { value: pick('bandwidth_mb', 1) })}
      ${pkgNumber('backups', 'Backups', { min: 1, max: 3, value: pick('backups', 1), unlimited: false, help: 'Entre 1 y 3.' })}
      ${fSelect('incremental_backup', 'Backup incremental', yesNo, { value: pick('incremental_backup', false) ? '1' : '0' })}

      ${formSection('WEB - APPS')}
      ${pkgNumber('web_domains', 'Dominios webs - apps', { value: pick('web_domains', 1) })}
      ${pkgNumber('web_aliases', 'Alias web', { value: pick('web_aliases', 1) })}
      ${fSelect('web_backend', 'Backend', WEB_BACKEND_OPTIONS, { value: pick('web_backend', 'php') })}
      ${fSelect('nginx_template', 'Plantilla proxy Nginx', nginxOptions, { value: pick('nginx_template', 'hosting') })}

      ${formSection('DNS')}
      ${fSelect('dns_template', 'Plantilla DNS', dnsOptions, { value: pick('dns_template', 'child-ns') })}
      ${pkgNumber('dns_zones', 'Zonas DNS', { value: pick('dns_zones', 0), disabled: true, unlimited: false, help: 'Valor calculado; no editable.' })}
      ${pkgNumber('dns_records', 'Registros DNS (por dominio)', { value: pick('dns_records', 0), disabled: true, unlimited: false, help: 'Valor calculado; no editable.' })}
      <div class="field full">
        <span>Servidores de nombre</span>
        <div class="stack" id="package-ns"></div>
        <button type="button" class="btn ghost tiny" data-add-ns>Añadir nombre de servidor</button>
        <small class="hint">Se usan como ns1/ns2 del dominio; puedes añadir más.</small>
      </div>

      ${formSection('Correo')}
      ${pkgNumber('mail_domains', 'Dominios de email', { value: pick('mail_domains', 1) })}
      ${pkgNumber('mail_accounts', 'Cuentas de email (por dominio)', { value: pick('mail_accounts', 5) })}
      ${pkgNumber('mail_rate_limit', 'Límite de tasas', { value: pick('mail_rate_limit', 0) })}

      ${formSection('Bases de datos')}
      ${pkgNumber('databases', 'Bases de datos', { value: pick('databases', 0) })}

      ${formSection('FTP')}
      ${pkgNumber('ftp_accounts', 'Cuentas FTP', { value: pick('ftp_accounts', 0) })}

      ${formSection('Sistema')}
      ${pkgNumber('system_databases', 'Bases de datos', { value: pick('system_databases', 0), help: 'Límite de bases de datos del sistema.' })}
    </div>`,
    onMount: (form) => {
      const nsRoot = form.querySelector('#package-ns');
      const addNameserver = (value = '') => {
        const row = document.createElement('div');
        row.className = 'limit-row';
        row.innerHTML = `<input name="nameservers" type="text" value="${esc(value)}" placeholder="ns1.example.tld">`;
        nsRoot.appendChild(row);
      };
      const initial = pkg && Array.isArray(pkg.nameservers) && pkg.nameservers.length
        ? pkg.nameservers
        : ['ns1.example.tld', 'ns2.example.tld'];
      initial.forEach(addNameserver);
      form.querySelector('[data-add-ns]').addEventListener('click', () => addNameserver(''));

      form.querySelectorAll('[data-limit]').forEach((button) => {
        button.addEventListener('click', () => {
          const input = form.elements[button.dataset.limit];
          if (input) input.value = '0';
        });
      });
    },
    onSubmit: async (form) => {
      const nameservers = Array.from(form.querySelectorAll('input[name="nameservers"]'))
        .map((input) => input.value.trim())
        .filter(Boolean);
      const payload = {
        name: val(form, 'name'),
        account_mb: num(form, 'account_mb'),
        bandwidth_mb: num(form, 'bandwidth_mb'),
        backups: num(form, 'backups', 1),
        incremental_backup: val(form, 'incremental_backup') === '1',
        web_domains: num(form, 'web_domains'),
        web_aliases: num(form, 'web_aliases'),
        web_backend: val(form, 'web_backend'),
        nginx_template: val(form, 'nginx_template'),
        dns_template: val(form, 'dns_template'),
        dns_zones: num(form, 'dns_zones'),
        dns_records: num(form, 'dns_records'),
        nameservers,
        mail_domains: num(form, 'mail_domains'),
        mail_accounts: num(form, 'mail_accounts'),
        mail_rate_limit: num(form, 'mail_rate_limit'),
        databases: num(form, 'databases'),
        system_databases: num(form, 'system_databases'),
        ftp_accounts: num(form, 'ftp_accounts'),
      };
      if (!payload.name) throw new Error('El nombre del paquete es obligatorio');
      if (pkg) {
        await api(`/api/v1/packages/${encodeURIComponent(pkg.id)}`, { method: 'PATCH', body: payload });
        toast('Paquete actualizado');
      } else {
        await api('/api/v1/packages', { method: 'POST', body: payload });
        toast('Paquete creado');
      }
      await refresh();
    },
  });
}

function isOwner() {
  return S.user && S.user.role === 'owner';
}

/* ---------------- audit ---------------- */

async function renderAudit() {
  const data = await api('/api/v1/audit?limit=250');
  const entries = (data.entries || []).slice().reverse();
  const rows = entries.map((entry) => [
    td(`<span class="chip">#${esc(entry.seq)}</span>`),
    td(esc(fmtDate(entry.at))),
    td(`<strong>${esc(entry.actor)}</strong>`),
    td(`<span class="mono small">${esc(entry.action)}</span>`),
    td(esc(entry.target)),
    td(`<span class="muted small">${esc(entry.detail)}</span>`),
  ]);

  $('#view').innerHTML =
    sectionHead('Registro encadenado', `<button class="btn ghost" data-action="reload">Actualizar</button>`) +
    table(['#', 'Fecha', 'Actor', 'Acción', 'Objetivo', 'Detalle'], rows, 'Sin eventos.');
}

/* ---------------- system ---------------- */

async function renderSystem() {
  const info = await loadSystem();
  const memUsed = info.mem_total_kb - info.mem_available_kb;
  const diskUsed = info.disk_total_kb - info.disk_available_kb;
  let mail = null;
  if (isAdmin()) {
    try {
      mail = await api('/api/v1/system/email');
    } catch {
      mail = null;
    }
  }

  let html = `<div class="grid cols-2">
    <div class="card">
      <div class="section-head"><h2>Identidad</h2>${badge(info.mode, info.mode === 'simulation' ? 'warn' : 'ok')}</div>
      <dl class="kv" style="margin-top:14px">
        <dt>Hostname</dt><dd>${esc(info.hostname)}</dd>
        <dt>Sistema</dt><dd>${esc(info.os)}</dd>
        <dt>Kernel</dt><dd>${esc(info.kernel)}</dd>
        <dt>Uptime</dt><dd>${esc(fmtUptime(info.uptime_secs))}</dd>
        <dt>vCPU</dt><dd>${esc(info.cpu_count)}</dd>
        <dt>Load</dt><dd>${(info.load || [0, 0, 0]).map((v) => (v / 100).toFixed(2)).join(' / ')}</dd>
        <dt>Daemon</dt><dd>v${esc(info.daemon_version)}</dd>
      </dl>
    </div>
    <div class="card">
      <div class="section-head"><h2>Capacidad</h2></div>
      <div class="stack" style="margin-top:16px">
        <div>
          <div class="muted small">Memoria · ${esc(fmtKb(memUsed))} / ${esc(fmtKb(info.mem_total_kb))}</div>
          <div class="bar" style="margin-top:6px"><i style="width:${pct(memUsed, info.mem_total_kb)}%"></i></div>
        </div>
        <div>
          <div class="muted small">Disco · ${esc(fmtKb(diskUsed))} / ${esc(fmtKb(info.disk_total_kb))}</div>
          <div class="bar" style="margin-top:6px"><i style="width:${pct(diskUsed, info.disk_total_kb)}%"></i></div>
        </div>
      </div>
    </div>
  </div>`;

  html += `<div class="card">
    <div class="section-head"><h2>Reconciliación</h2>
      ${isAdmin() ? '<button class="btn primary" data-action="reconcile">Re-aplicar estado</button>' : badge('solo lectura', '')}
    </div>
    <p class="muted small" style="margin:12px 0 0">
      El motor declarativo vuelve a renderizar vhosts, pools, unidades systemd y permisos
      a partir del estado persistido. Úsalo tras cambios manuales o recuperaciones.
    </p>
  </div>`;

  if (mail) {
    html += `<div class="card">
      <div class="section-head"><h2>Correo del panel</h2>
        ${mail.enabled ? badge('activo', 'ok') : badge('desactivado', 'warn')}
      </div>
      <dl class="kv" style="margin-top:14px">
        <dt>Servidor SMTP</dt><dd class="mono">${esc(mail.host)}:${esc(mail.port)}</dd>
        <dt>TLS</dt><dd>${esc(mail.tls)}</dd>
        <dt>Remitente</dt><dd>${esc(mail.from || '-')}</dd>
        <dt>Avisos</dt><dd>${esc(mail.alert_to || '-')}</dd>
        <dt>URL pública</dt><dd>${esc(mail.public_url || '-')}</dd>
      </dl>
      <p class="muted small" style="margin:14px 0 0">
        Se usa Postfix local para credenciales, restablecimiento de contraseña y avisos de certificados.
        SPF, DKIM y DMARC se publican en la zona del dominio del panel.
      </p>
      ${mail.enabled
        ? '<div class="row-inline" style="margin-top:14px"><button class="btn primary" data-action="email-test">Enviar prueba</button></div>'
        : '<p class="muted small" style="margin:14px 0 0">Configura smtp_enabled y smtp_from en /etc/rynxcp/api.toml.</p>'}
    </div>`;
  }

  $('#view').innerHTML = html;
}

function openEmailTestModal() {
  openModal({
    title: 'Probar correo del panel',
    submitLabel: 'Enviar prueba',
    html: `<div class="stack">${fInput('to', 'Destinatario', {
      type: 'email',
      placeholder: 'admin@example.com',
      help: 'Vacío usa smtp_alert_to o tu email de usuario.',
    })}</div>`,
    onSubmit: async (form) => {
      const result = await api('/api/v1/system/email/test', {
        method: 'POST',
        body: { to: val(form, 'to') || null },
      });
      toast(TF('Correo de prueba enviado a {to}', { to: result.to }));
    },
  });
}

/* ---------------- actions ---------------- */

async function handleAction(action, id) {
  switch (action) {
    case 'reload':
      return refresh();
    case 'account-new':
      return openAccountModal();
    case 'account-toggle': {
      const account = S.data.accounts.find((a) => a.spec.username === id);
      if (!account) throw new Error('Cuenta no encontrada');
      await api('/api/v1/accounts', {
        method: 'POST',
        body: { ...account.spec, enabled: !account.spec.enabled },
      });
      toast(account.spec.enabled ? 'Cuenta suspendida' : 'Cuenta activada');
      return refresh();
    }
    case 'account-ssh': {
      const account = S.data.accounts.find((a) => a.spec.username === id);
      if (!account) throw new Error('Cuenta no encontrada');
      await api('/api/v1/accounts', {
        method: 'POST',
        body: { ...account.spec, ssh_enabled: !account.spec.ssh_enabled },
      });
      toast(T('Actualizado'));
      return refresh();
    }
    case 'account-panel-access': {
      const account = S.data.accounts.find((a) => a.spec.username === id);
      if (!account) throw new Error('Cuenta no encontrada');
      const result = await api('/api/v1/accounts', {
        method: 'POST',
        body: { ...account.spec, panel_access: true, panel_role: 'viewer' },
      });
      if (result.panel_password) {
        showOutput(
          T('Acceso al panel creado'),
          `${T('usuario:')} ${result.panel_user.username}\n` +
            `${T('contraseña:')} ${result.panel_password}\n\n` +
            `${T('Entra en')} ${location.origin}.\n` +
            T('El acceso es de solo lectura (viewer).'),
        );
      } else {
        toast('El acceso ya existía');
      }
      return refresh();
    }
    case 'account-delete': {
      if (!confirm(TF('¿Eliminar la cuenta {id}? Se borrarán el home, sitios, apps, bases de datos, DNS, FTP, certificados y backups.', { id }))) return;
      await api(`/api/v1/accounts/${encodeURIComponent(id)}?purge=true`, { method: 'DELETE' });
      toast('Cuenta eliminada');
      return refresh();
    }
    case 'account-backend':
      return openBackendModal(id);
    case 'account-limits': {
      const assignment = (S.data.accountPackages || []).find((item) => item.account === id);
      const pkg = assignment
        ? (S.data.packages || []).find((item) => item.id === assignment.package_id)
        : null;
      if (!pkg) throw new Error('Paquete no encontrado');
      openModal({
        title: `Límites · ${id}`,
        submitLabel: 'Cerrar',
        html: packageSummary(pkg),
        onSubmit: async () => {},
      });
      return;
    }
    case 'mail-new':
      return openMailEnableModal();
    case 'mail-enable':
      return enableMail(id);
    case 'mail-toggle':
      return toggleMailDomain(id);
    case 'mail-account-new':
      return openMailAccountModal(id);
    case 'mail-account-passwd':
      return openMailPasswordModal(mailAccountById(id));
    case 'mail-account-toggle':
      return toggleMailAccount(mailAccountById(id));
    case 'mail-account-delete': {
      const account = mailAccountById(id);
      if (!account) throw new Error('Buzón no encontrado');
      if (!confirm(TF('¿Eliminar el buzón {address}? Se borrará su correo almacenado.', { address: account.address }))) return;
      await api(`/api/v1/mail/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Buzón eliminado');
      return refresh();
    }
    case 'mail-catchall':
      return openMailCatchAllModal(id);
    case 'mail-tls':
      return retryMailTls(id);
    case 'mail-delete': {
      if (!confirm(TF('¿Eliminar el correo de {id}? Se borrarán los buzones y el webmail.', { id }))) return;
      await api(`/api/v1/mail/domains/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Correo eliminado');
      return refresh();
    }
    case 'website-new':
      return openWebsiteModal();
    case 'website-edit': {
      const site = (S.data.websites || []).find((item) => item.spec.domain === id);
      if (site) return openWebsiteModal(site);
      return undefined;
    }
    case 'files-refresh':
      return navigate('files');
    case 'file-open':
      S.files.path = id;
      return navigate('files');
    case 'file-edit':
      return openFileEditor(id);
    case 'file-download':
      return downloadFile(id);
    case 'file-rename':
      return renameFile(id);
    case 'file-delete':
      return deleteFile(id);
    case 'file-new-folder':
      return openNewFolderModal();
    case 'website-files':
      S.files.domain = id;
      S.files.path = '';
      return navigate('files');
    case 'website-delete': {
      if (!confirm(TF('¿Eliminar el sitio {id} y todo lo asociado (base de datos, correo/webmail, FTP, certificado y DNS)?', { id }))) return;
      await api(`/api/v1/websites/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Sitio eliminado');
      return refresh();
    }
    case 'app-new':
      return openAppModal();
    case 'installer-new':
      return openInstallerModal(id);
    case 'app-delete': {
      if (!confirm(TF('¿Eliminar la aplicación {id}?', { id }))) return;
      const [user, name] = id.split('/');
      await api(`/api/v1/apps/${encodeURIComponent(user)}/${encodeURIComponent(name)}`, { method: 'DELETE' });
      toast('Aplicación eliminada');
      return refresh();
    }
    case 'php-new':
      return openPhpModal();
    case 'php-delete': {
      if (!confirm(TF('¿Eliminar el pool PHP de {id}?', { id }))) return;
      await api(`/api/v1/php-pools/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Pool eliminado');
      return refresh();
    }
    case 'cert-new':
      return openCertModal();
    case 'cert-reissue': {
      const email = S.user.email;
      const job = await api('/api/v1/certs/jobs', {
        method: 'POST',
        body: { domain: id, email, staging: false },
      });
      return showCertJob(job, id, { email, staging: false });
    }
    case 'user-new':
      return openUserModal();
    case 'user-toggle': {
      const user = S.data.users.find((u) => u.username === id);
      if (!user) throw new Error('Usuario no encontrado');
      if (user.username === S.user.username) throw new Error('No puedes desactivar tu propia cuenta');
      await api(`/api/v1/users/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: { active: !user.active },
      });
      toast(user.active ? 'Usuario desactivado' : 'Usuario activado');
      return refresh();
    }
    case 'user-passwd': {
      openModal({
        title: T('Nueva contraseña') + ' · ' + id,
        submitLabel: 'Actualizar',
        html: `<div class="stack">${fInput('password', 'Contraseña', { type: 'password', required: true, autocomplete: 'new-password', help: 'mínimo 12 caracteres, 3 clases; revoca sesiones' })}</div>`,
        onSubmit: async (form) => {
          await api(`/api/v1/users/${encodeURIComponent(id)}`, {
            method: 'PATCH',
            body: { password: val(form, 'password') },
          });
          toast('Contraseña actualizada');
        },
      });
      return;
    }
    case 'user-delete': {
      if (!confirm(TF('¿Eliminar al usuario {id}? Si tiene una cuenta de hosting, también se borrarán su cuenta y todos sus datos.', { id }))) return;
      await api(`/api/v1/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Usuario eliminado');
      return refresh();
    }
    case 'reconcile': {
      const result = await api('/api/v1/reconcile', { method: 'POST' });
      toast(result.message || 'Estado re-aplicado');
      return refresh();
    }
    case 'email-test':
      return openEmailTestModal();
    case 'impersonate': {
      const data = await api(`/api/v1/users/${encodeURIComponent(id)}/impersonate`, { method: 'POST' });
      S.user = data.user;
      S.csrf = data.csrf_token;
      S.impersonatedBy = data.impersonated_by || null;
      enterApp();
      toast(`${T('Ahora viendo el panel como')} ${data.user.username}`);
      return;
    }
    case 'cert-renew': {
      const result = await api('/api/v1/certs/renew', { method: 'POST' });
      toast(result.message || 'Certificados renovados');
      return refresh();
    }
    case 'reveal': {
      const el = document.querySelector(`[data-secret="${id}"]`);
      if (el) {
        el.textContent = el.dataset.value || '';
        el.classList.remove('secret');
      }
      return;
    }
    case 'database-new':
      return openDatabaseModal();
    case 'database-delete': {
      if (!confirm('¿Eliminar esta base de datos y su usuario? Los datos se perderán.')) return;
      await api(`/api/v1/databases/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Base de datos eliminada');
      return refresh();
    }
    case 'ftp-new':
      return openFtpModal();
    case 'ftp-delete': {
      if (!confirm('¿Eliminar este usuario FTP?')) return;
      await api(`/api/v1/ftp/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Usuario FTP eliminado');
      return refresh();
    }
    case 'dns-record-new':
      return openDnsRecordModal();
    case 'dns-record-delete': {
      const split = id.indexOf('/');
      const domain = id.slice(0, split);
      const recordId = id.slice(split + 1);
      if (!confirm('¿Eliminar este registro DNS?')) return;
      await api(`/api/v1/dns/${encodeURIComponent(domain)}/records/${encodeURIComponent(recordId)}`, { method: 'DELETE' });
      toast('Registro eliminado');
      return refresh();
    }
    case 'dns-mail': {
      if (!S.dnsDomain) return;
      await api(`/api/v1/dns/${encodeURIComponent(S.dnsDomain)}/mail`, { method: 'POST' });
      toast('SPF, DKIM, DMARC y MX provisionados');
      return refresh();
    }
    case 'backup-new':
      return openBackupModal();
    case 'backup-delete': {
      if (!confirm('¿Eliminar esta copia de seguridad?')) return;
      await api(`/api/v1/backups/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Backup eliminado');
      return refresh();
    }
    case 'backup-restore': {
      if (!confirm('¿Restaurar esta copia? Se sobrescribirán archivos del home y la configuración gestionada.')) return;
      const result = await api(`/api/v1/backups/${encodeURIComponent(id)}/restore`, { method: 'POST' });
      toast(result.message || 'Backup restaurado');
      return refresh();
    }
    case 'cron-new':
      return openCronModal();
    case 'ssh-key-add':
      return openSshKeyModal();
    case 'ssh-key-delete': {
      const key = (S.data.sshKeys || [])[Number(id)];
      if (!key) return;
      await api('/api/v1/ssh/keys', { method: 'DELETE', body: { key } });
      toast('Clave SSH eliminada');
      return refresh();
    }
    case 'cron-toggle':
      return toggleCron(id);
    case 'cron-delete': {
      if (!confirm('¿Eliminar esta tarea cron?')) return;
      await api(`/api/v1/cron/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Tarea cron eliminada');
      return refresh();
    }
    case 'firewall-rule-new':
      return openFirewallRuleModal();
    case 'firewall-rule-delete': {
      if (!confirm('¿Eliminar esta regla del cortafuegos?')) return;
      await api(`/api/v1/firewall/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Regla eliminada');
      return refresh();
    }
    case 'firewall-block-new':
      return openFirewallBlockModal();
    case 'firewall-unblock': {
      if (!confirm(TF('¿Eliminar el baneo de {ip}?', { ip: id }))) return;
      await api(`/api/v1/firewall/block/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('IP desbloqueada');
      return refresh();
    }
    case 'firewall-whitelist-new':
      return openWhitelistModal();
    case 'firewall-whitelist-remove': {
      await api(`/api/v1/firewall/whitelist/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('IP retirada de la lista blanca');
      return refresh();
    }
    case 'program-restart':
    case 'program-stop': {
      const verb = action === 'program-restart' ? 'restart' : 'stop';
      await api(`/api/v1/system/programs/${encodeURIComponent(id)}/${verb}`, { method: 'POST' });
      toast(T(verb === 'restart' ? 'Programa reiniciado' : 'Programa detenido'));
      return refresh();
    }
    case 'agent-run': {
      const result = await api('/api/v1/agent/run', { method: 'POST' });
      toast(TF('Análisis completado: {count} hallazgo(s)', { count: result.total_findings || 0 }));
      return refresh();
    }
    case 'agent-test-provider': {
      const result = await api('/api/v1/agent/provider/test', { method: 'POST' });
      if (!result.ok) {
        toast(result.error || T('Proveedor no disponible'), 'error');
        return;
      }
      const provider = result.provider;
      showOutput(
        T('Prueba del proveedor'),
        `${provider.provider} · ${provider.mode}\n${provider.model}\n${provider.endpoint}\n${provider.latency_ms} ms\n\n${provider.summary || '—'}`,
      );
      return;
    }
    case 'agent-detail': {
      const finding = (S.data.agentFindings || []).find((item) => item.id === id);
      if (!finding) throw new Error('Hallazgo no encontrado');
      const evidence = (finding.evidence || []).map((line) => `· ${line}`).join('\n') || '—';
      showOutput(
        T('Hallazgo del agente'),
        `${finding.title}\n\n${finding.summary}\n\n${T('Evidencia')}:\n${evidence}\n\n${T('Recomendación')}:\n${finding.recommendation || '—'}`,
      );
      return;
    }
    case 'agent-ack':
      await api(`/api/v1/agent/findings/${encodeURIComponent(id)}/status`, { method: 'POST', body: { status: 'acknowledged' } });
      toast('Hallazgo marcado como revisado');
      return refresh();
    case 'agent-ignore':
      await api(`/api/v1/agent/findings/${encodeURIComponent(id)}/status`, { method: 'POST', body: { status: 'ignored' } });
      toast('Hallazgo ignorado');
      return refresh();
    case 'agent-reopen':
      await api(`/api/v1/agent/findings/${encodeURIComponent(id)}/status`, { method: 'POST', body: { status: 'open' } });
      toast('Hallazgo reabierto');
      return refresh();
    case 'updates-apply': {
      if (!confirm('¿Actualizar todos los paquetes del sistema ahora? Puede reiniciar servicios.')) return;
      const result = await api('/api/v1/system/updates/apply', { method: 'POST' });
      showOutput(T('Actualización completada'), result.output || T('Sin salida.'));
      return refresh();
    }
    case 'package-new':
      return openPackageModal();
    case 'package-edit': {
      const pkg = S.data.packages.find((item) => item.id === id);
      if (!pkg) throw new Error('Paquete no encontrado');
      return openPackageModal(pkg);
    }
    case 'package-delete': {
      const pkg = S.data.packages.find((item) => item.id === id);
      if (!pkg) throw new Error('Paquete no encontrado');
      if (pkg.is_default) throw new Error('El paquete Por defecto no se puede eliminar');
      if (!confirm(TF('¿Eliminar el paquete {name}?', { name: pkg.name }))) return;
      await api(`/api/v1/packages/${encodeURIComponent(id)}`, { method: 'DELETE' });
      toast('Paquete eliminado');
      return refresh();
    }
    default:
      throw new Error(`Acción desconocida: ${action}`);
  }
}

/* ---------------- databases ---------------- */

async function renderDatabases() {
  await Promise.all([loadList('databases'), loadList('websites')]);
  const writable = canWrite();
  const rows = S.data.databases.map((db) => [
    td(`<div class="cell-title">${esc(db.domain)}</div><div class="cell-sub">${esc(db.host)}</div>`),
    td(`<span class="mono small">${esc(db.username)}</span>`),
    td(`<span class="secret mono small" data-secret="${esc(db.id)}" data-value="${esc(db.password)}">${esc(db.password)}</span> ${btn('Ver', 'reveal', db.id)}`),
    td(esc(db.engine)),
    td(esc(fmtDate(db.created_at))),
    td(writable ? btn('Eliminar', 'database-delete', db.id, 'tiny danger') : '', 'actions'),
  ]);
  const phpMyAdmin = '<a class="btn ghost" href="/phpmyadmin/" target="_blank" rel="noopener noreferrer">phpMyAdmin</a>';
  $('#view').innerHTML =
    sectionHead('Bases de datos por dominio', phpMyAdmin + (writable ? '<button class="btn primary" data-action="database-new">Nueva base</button>' : '')) +
    table(['Dominio', 'Usuario', 'Contraseña', 'Motor', 'Creada', ''], rows, 'Crea bases de datos aisladas para tus sitios.');
}

function openDatabaseModal() {
  const candidates = S.data.websites;
  if (!candidates.length) {
    toast('Primero publica un sitio', 'error');
    return;
  }
  openModal({
    title: 'Nueva base de datos',
    submitLabel: 'Crear base',
    html: `<div class="form-grid">
      ${fSelect('domain', 'Sitio', candidates.map((w) => ({ value: w.spec.domain, label: w.spec.domain })), { required: true })}
      ${fInput('name', 'Nombre corto', { required: true, placeholder: 'tienda', help: 'La base y el usuario serán <cuenta>_<nombre>.' })}
      <p class="hint full">Puedes crear varias bases para el mismo sitio. Se crea una base utf8mb4 y un usuario MariaDB con contraseña aleatoria de 32 caracteres. Solo puede acceder por socket local.</p>
    </div>`,
    onSubmit: async (form) => {
      const result = await api('/api/v1/databases', { method: 'POST', body: { domain: val(form, 'domain'), name: val(form, 'name') } });
      const db = result.database;
      showOutput(T('Base de datos creada'), `${T('dominio:')} ${db.domain}\n${T('usuario:')} ${db.username}\n${T('contraseña:')} ${db.password}\n${T('host:')} ${db.host}\n\n${T('Guarda la contraseña ahora.')}`);
      await refresh();
    },
  });
}

/* ---------------- ftp ---------------- */

async function renderFtp() {
  await Promise.all([loadList('ftp'), loadList('websites')]);
  const writable = canWrite();
  const rows = S.data.ftp.map((account) => [
    td(`<div class="cell-title">${esc(account.login)}</div><div class="cell-sub">${esc(account.domain)}</div>`),
    td(`<span class="mono small">${esc(account.home)}</span>`),
    td(account.readonly ? badge('solo lectura', 'warn') : badge('lectura/escritura', 'ok')),
    td(`<span class="secret mono small" data-secret="${esc(account.id)}" data-value="${esc(account.password)}">${esc(account.password)}</span> ${btn('Ver', 'reveal', account.id)}`),
    td(esc(fmtDate(account.created_at))),
    td(writable ? btn('Eliminar', 'ftp-delete', account.id, 'tiny danger') : '', 'actions'),
  ]);
  $('#view').innerHTML =
    sectionHead('Usuarios FTP', writable ? '<button class="btn primary" data-action="ftp-new">Nuevo usuario FTP</button>' : '') +
    table(['Login', 'Home (chroot)', 'Permisos', 'Contraseña', 'Creado', ''], rows, 'Crea usuarios FTPS con chroot al home de la cuenta.');
}

function openFtpModal() {
  if (!S.data.websites.length) {
    toast('Primero publica un sitio', 'error');
    return;
  }
  openModal({
    title: 'Nuevo usuario FTP',
    submitLabel: 'Crear usuario',
    html: `<div class="form-grid">
      ${fSelect('domain', 'Sitio', S.data.websites.map((w) => ({ value: w.spec.domain, label: w.spec.domain })), { required: true })}
      ${fInput('username', 'Nombre corto', { required: true, placeholder: 'deploy', help: 'se usará como <cuenta>_<nombre>' })}
      ${fInput('password', 'Contraseña', { type: 'password', placeholder: 'vacío = generar', help: 'mínimo 12 caracteres, 3 clases', autocomplete: 'new-password' })}
      <div class="full">${fCheck('readonly', 'Solo lectura (sin escritura en el home)', false)}</div>
    </div>`,
    onSubmit: async (form) => {
      const body = { domain: val(form, 'domain'), username: val(form, 'username').toLowerCase(), readonly: bool(form, 'readonly') };
      const password = val(form, 'password');
      if (password) body.password = password;
      const result = await api('/api/v1/ftp', { method: 'POST', body });
      showOutput(T('Usuario FTP creado'), `${T('login:')} ${result.account.login}\n${T('contraseña:')} ${result.account.password}\n${T('home:')} ${result.account.home}\n\n${T('Usa FTPS explícito (puerto 21).')}`);
      await refresh();
    },
  });
}

/* ---------------- dns ---------------- */

async function renderDns() {
  const data = await api('/api/v1/dns');
  const writable = canWrite();
  const zones = data.zones || [];
  if (!zones.length) {
    $('#view').innerHTML = `<div class="card empty"><strong>Sin zonas DNS</strong><span>Publica un sitio con DNS habilitado para generar automáticamente SOA, NS, A, SPF, DKIM, DMARC y MX.</span></div>`;
    return;
  }
  const selected = zones.find((zone) => zone.domain === S.dnsDomain) || zones[0];
  S.dnsDomain = selected.domain;
  const rows = selected.records.map((record) => [
    td(`<span class="mono">${esc(record.spec.name)}</span>`),
    td(`<span class="chip">${esc(record.spec.rtype)}</span>`),
    td(`<span class="mono small">${esc(record.spec.value)}</span>`),
    td(esc(record.spec.ttl)),
    td(record.managed ? badge('auto', 'info') : badge('manual', '')),
    td(writable ? btn('Eliminar', 'dns-record-delete', `${selected.domain}/${record.id}`, 'tiny danger') : '', 'actions'),
  ]);
  const options = zones.map((zone) => `<option value="${esc(zone.domain)}" ${zone.domain === selected.domain ? 'selected' : ''}>${esc(zone.domain)}</option>`).join('');
  $('#view').innerHTML = `
    <div class="section-head">
      <div class="row-inline">
        <h2>Zona</h2>
        <select id="dns-zone-select" class="compact">${options}</select>
      </div>
      <div class="row-inline">
        ${writable ? '<button class="btn ghost" data-action="dns-mail">Provisionar correo</button><button class="btn primary" data-action="dns-record-new">Añadir registro</button>' : ''}
      </div>
    </div>
    <div class="grid cols-4">
      <div class="card stat"><div class="label">Servidores NS</div><div class="value small-value mono">${esc(selected.nameservers.join(', ') || 'sin configurar')}</div></div>
      <div class="card stat"><div class="label">Serial</div><div class="value">${esc(selected.serial)}</div></div>
      <div class="card stat"><div class="label">Correo</div><div class="value small-value">${selected.mail_ready ? badge('preparado', 'ok') : badge('pendiente', 'warn')}</div><div class="hint">SPF · DKIM · DMARC · MX</div></div>
      <div class="card stat"><div class="label">Fichero</div><div class="value small-value mono">${esc(selected.zone_file)}</div></div>
    </div>
    ${table(['Nombre', 'Tipo', 'Valor', 'TTL', 'Origen', ''], rows, 'Sin registros.')}
    <div class="card">
      <strong>Entregabilidad de correo</strong>
      <p class="muted small" style="margin:8px 0 0">
        La zona incluye SPF, DKIM (<span class="mono">${esc(selected.dkim_selector)}._domainkey</span>), DMARC y MX.
        El PTR inverso se configura en el proveedor de la IP: debe resolver a <span class="mono">${esc(S.mailHost || 'mail.' + selected.domain)}</span>.
        Verifica con <span class="mono">dig -x TU_IP</span> antes de enviar correo masivo.
      </p>
    </div>`;

  $('#dns-zone-select').addEventListener('change', (event) => {
    S.dnsDomain = event.target.value;
    renderDns();
  });
}

function openDnsRecordModal() {
  const domain = S.dnsDomain;
  if (!domain) return;
  openModal({
    title: T('Nuevo registro') + ' · ' + domain,
    submitLabel: 'Guardar',
    html: `<div class="form-grid">
      ${fInput('name', 'Nombre', { value: '@', required: true, help: '@, www, _dmarc, mail._domainkey…' })}
      ${fSelect('rtype', 'Tipo', ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA'], { value: 'A' })}
      ${fInput('value', 'Valor', { required: true, placeholder: '203.0.113.10' })}
      ${fInput('ttl', 'TTL', { type: 'number', value: 300, min: 60, max: 86400, required: true })}
      ${fInput('priority', 'Prioridad (MX)', { type: 'number', value: 10, min: 0, max: 65535 })}
      <p class="hint full">Nota: se admite un registro por combinación nombre + tipo.</p>
    </div>`,
    onSubmit: async (form) => {
      const rtype = val(form, 'rtype');
      await api(`/api/v1/dns/${encodeURIComponent(domain)}/records`, {
        method: 'POST',
        body: {
          domain,
          name: val(form, 'name'),
          rtype,
          value: val(form, 'value'),
          ttl: num(form, 'ttl', 300),
          priority: rtype === 'MX' ? num(form, 'priority', 10) : null,
        },
      });
      toast('Registro DNS guardado');
      await refresh();
    },
  });
}

/* ---------------- backups ---------------- */

async function renderBackups() {
  await Promise.all([loadList('backups'), loadList('accounts')]);
  const writable = canWrite();
  const scoped = isScoped();
  const rows = S.data.backups.map((backup) => [
    td(`<div class="cell-title">${esc(backup.username)}</div><div class="cell-sub mono">${esc(backup.id)}</div>`),
    td(esc(fmtDate(backup.created_at))),
    td(esc(fmtBytes(backup.size_bytes))),
    td(badge(backup.status, backup.status === 'simulated' ? 'warn' : 'ok')),
    td(`<span class="mono small">${esc(backup.path)}</span>`),
    td([
      writable ? `<a class="btn tiny ghost" href="/api/v1/backups/${encodeURIComponent(backup.id)}/download">Descargar</a>` : '',
      isAdmin() && !scoped ? btn('Restaurar', 'backup-restore', backup.id, 'tiny ghost') : '',
      writable ? btn('Eliminar', 'backup-delete', backup.id, 'tiny danger') : '',
    ].join(''), 'actions'),
  ]);
  $('#view').innerHTML =
    sectionHead('Copias de seguridad', writable ? '<button class="btn primary" data-action="backup-new">Crear backup</button>' : '') +
    table(['Cuenta', 'Fecha', 'Tamaño', 'Estado', 'Ruta', ''], rows, 'Aún no hay copias. Se conservan las últimas 7 por cuenta.');
}

async function renderCron() {
  await Promise.all([loadList('cron'), loadList('accounts')]);
  const writable = canWrite();
  const rows = (S.data.cron || []).map((job) => [
    td(`<div class="cell-title">${esc(job.username)}</div><div class="cell-sub mono">${esc(job.schedule)}</div>`),
    td(`<span class="mono small">${esc(job.command)}</span>`),
    td(job.enabled ? badge('activo', 'ok') : badge('desactivado', 'warn')),
    td(esc(fmtDate(job.created_at))),
    td(writable ? [
      btn(job.enabled ? 'Desactivar' : 'Activar', 'cron-toggle', job.id, 'tiny ghost'),
      btn('Eliminar', 'cron-delete', job.id, 'tiny danger'),
    ].join('') : '', 'actions'),
  ]);
  $('#view').innerHTML =
    sectionHead('Cron', writable ? '<button class="btn primary" data-action="cron-new">Nueva tarea</button>' : '') +
    table(['Cuenta', 'Comando', 'Estado', 'Creada', ''], rows, 'No hay tareas programadas. Se ejecutan con el usuario de la cuenta.');
}

async function renderSsh() {
  const data = await api('/api/v1/ssh');
  S.data.sshKeys = data.keys || [];
  const writable = canWrite();
  const rows = S.data.sshKeys.map((key, index) => {
    const parts = key.split(/\s+/);
    return [
      td(`<div class="cell-title">${esc(parts[0] || 'SSH')}</div><div class="cell-sub mono">${esc(key.length > 90 ? key.slice(0, 90) + '…' : key)}</div>`),
      td(writable ? btn('Eliminar', 'ssh-key-delete', String(index), 'tiny danger') : '', 'actions'),
    ];
  });
  $('#view').innerHTML =
    sectionHead('SSH', writable ? '<button class="btn primary" data-action="ssh-key-add">Añadir clave</button>' : '') +
    `<div class="card"><p class="muted small" style="margin:0">${T('Conéctate con:')} <span class="mono">ssh ${esc(data.username)}@${esc(data.host)} -p ${esc(data.port)}</span></p></div>` +
    table(['SSH', ''], rows, 'No hay claves SSH. Añade una clave pública para conectarte.');
}

function openSshKeyModal() {
  openModal({
    title: 'Añadir clave SSH',
    submitLabel: 'Añadir',
    html: fTextarea('key', 'Clave pública SSH', {
      placeholder: 'ssh-ed25519 AAAA... usuario@equipo',
      full: true,
      help: 'Pega solo la clave pública; la clave privada nunca se envía al panel.',
    }),
    onSubmit: async (form) => {
      await api('/api/v1/ssh/keys', {
        method: 'POST',
        body: { key: val(form, 'key') },
      });
      toast('Clave SSH añadida');
      await refresh();
    },
  });
}

function openCronModal() {
  const accounts = accountOptions(false);
  if (!accounts.length) {
    toast('Primero crea una cuenta', 'error');
    return;
  }
  openModal({
    title: 'Nueva tarea cron',
    submitLabel: 'Crear tarea',
    html: `<div class="form-grid">
      ${fSelect('username', 'Cuenta', accounts, { required: true })}
      ${fInput('schedule', 'Programación', { required: true, value: '*/5 * * * *', placeholder: '*/5 * * * *', help: 'Cinco campos: minuto hora día mes día-semana.' })}
      <div class="full">${field('command', 'Comando', '<textarea name="command" rows="3" required placeholder="php /home/cuenta/example.com/public_html/artisan schedule:run"></textarea>', 'Se ejecuta con el shell y el usuario de la cuenta; no puede contener % ni saltos de línea.', true)}</div>
      <div class="full">${fCheck('enabled', 'Activa', true)}</div>
    </div>`,
    onSubmit: async (form) => {
      await api('/api/v1/cron', {
        method: 'POST',
        body: {
          username: val(form, 'username'),
          schedule: val(form, 'schedule'),
          command: val(form, 'command'),
          enabled: bool(form, 'enabled'),
        },
      });
      toast('Tarea cron creada');
      await refresh();
    },
  });
}

async function toggleCron(id) {
  const job = (S.data.cron || []).find((item) => item.id === id);
  if (!job) throw new Error('Tarea no encontrada');
  await api('/api/v1/cron', {
    method: 'POST',
    body: {
      id: job.id,
      username: job.username,
      schedule: job.schedule,
      command: job.command,
      enabled: !job.enabled,
    },
  });
  toast(job.enabled ? 'Tarea desactivada' : 'Tarea activada');
  await refresh();
}

function openBackupModal() {
  if (!S.data.accounts.length) {
    toast('Primero crea una cuenta', 'error');
    return;
  }
  openModal({
    title: 'Crear backup',
    submitLabel: 'Crear',
    html: `<div class="form-grid">${fSelect('username', 'Cuenta', accountOptions(false), { required: true })}</div>`,
    onSubmit: async (form) => {
      await api('/api/v1/backups', { method: 'POST', body: { username: val(form, 'username') } });
      toast('Backup creado');
      await refresh();
    },
  });
}

/* ---------------- monitor ---------------- */

function sparkline(samples, pick, color, suffix = '') {
  if (!samples || samples.length < 2) return `<div class="empty small">Recopilando datos…</div>`;
  const values = samples.map(pick);
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = Math.max(max - min, 1);
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * 600;
      const y = 112 - ((value - min) / span) * 100;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
  return `<svg class="spark" viewBox="0 0 600 120" preserveAspectRatio="none" aria-hidden="true"><polyline fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke" points="${points}"/></svg><div class="muted small">${esc(suffix)}</div>`;
}

async function renderMonitor() {
  const [servicesData, historyData] = await Promise.all([
    api('/api/v1/monitor/services'),
    api('/api/v1/monitor/history?minutes=1440'),
  ]);
  const services = servicesData.services || [];
  const samples = historyData.samples || [];
  const active = services.filter((s) => s.status === 'active').length;
  const last = samples[samples.length - 1];

  const rows = services.map((service) => [
    td(`<span class="chip">${esc(service.kind)}</span>`),
    td(`<div class="cell-title">${esc(service.name)}</div><div class="cell-sub mono">${esc(service.unit)}</div>`),
    td(service.status === 'active' ? badge('activo', 'ok') : service.status === 'failed' ? badge('fallido', 'bad') : badge(service.status, 'warn')),
    td(`${service.cpu_percent.toFixed(2)} %`),
    td(esc(fmtKb(service.memory_kb))),
    td(esc(fmtUptime(service.uptime_secs))),
  ]);

  $('#view').innerHTML = `
    <div class="grid cols-4">
      <div class="card stat"><div class="label">Servicios</div><div class="value">${active}/${services.length}</div><div class="hint">activos ahora</div></div>
      <div class="card stat"><div class="label">Load 1m</div><div class="value">${last ? (last.load1 / 100).toFixed(2) : '—'}</div><div class="hint">media 1 minuto</div></div>
      <div class="card stat"><div class="label">Memoria usada</div><div class="value small-value">${last ? esc(fmtKb(last.mem_used_kb)) : '—'}</div><div class="hint">última muestra</div></div>
      <div class="card stat"><div class="label">Disco usado</div><div class="value small-value">${last ? esc(fmtKb(last.disk_used_kb)) : '—'}</div><div class="hint">última muestra</div></div>
    </div>
    <div class="grid cols-2">
      <div class="card"><div class="section-head"><h2>Load</h2><span class="badge info">24 h</span></div><div class="chart">${sparkline(samples, (s) => s.load1, '#57e6a1')}</div></div>
      <div class="card"><div class="section-head"><h2>Memoria</h2><span class="badge info">24 h</span></div><div class="chart">${sparkline(samples, (s) => s.mem_used_kb, '#4cc9f0')}</div></div>
      <div class="card"><div class="section-head"><h2>Disco</h2><span class="badge info">24 h</span></div><div class="chart">${sparkline(samples, (s) => s.disk_used_kb, '#ffc857')}</div></div>
      <div class="card"><div class="section-head"><h2>Servicios activos</h2><span class="badge info">24 h</span></div><div class="chart">${sparkline(samples, (s) => s.services_active, '#a78bfa')}</div></div>
    </div>
    ${sectionHead('Servicios', '<span class="muted small">actualizado cada 60 s</span>')}
    ${table(['Tipo', 'Servicio', 'Estado', 'CPU media', 'RAM', 'Uptime'], rows, 'No hay servicios registrados.')}`;
}

/* ---------------- antivirus and antispam ---------------- */

const FILTER_SERVICE_LABELS = {
  'clamav-daemon': 'ClamAV',
  'clamav-milter': 'ClamAV milter',
  spamd: 'SpamAssassin',
  spamassassin: 'SpamAssassin',
  'spamass-milter': 'SpamAssassin milter',
  'rynxcp-antivirus': 'Análisis programado',
};

function filterServiceLabel(unit) {
  return T(FILTER_SERVICE_LABELS[unit] || unit);
}

function filterSeverityBadge(severity) {
  if (severity === 'alert') return badge('detección', 'bad');
  if (severity === 'error') return badge('error', 'bad');
  if (severity === 'warn') return badge('aviso', 'warn');
  return badge('información', 'info');
}

function filterComponentTable(programs, emptyText) {
  const rows = programs.map((program) => [
    td(`<div class="cell-title">${esc(program.name)}</div><div class="cell-sub">${esc(program.detail)}</div>`),
    td(`<span class="mono small">${esc(program.version)}</span>`),
    td(program.status === 'installed' ? badge('instalado', 'ok') : badge('ausente', 'warn')),
    td(programServiceBadge(program)),
    td(programUnit(program) && program.status === 'installed' ? [
      programButton('program-restart', program.name, 'Reiniciar', '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>'),
      programButton('program-stop', program.name, 'Parar', '<rect x="6" y="6" width="12" height="12" rx="1"/>'),
    ].join(' ') : '', 'actions'),
  ]);
  return table(['Componente', 'Versión', 'Paquete', 'Servicio', 'Acciones'], rows, emptyText);
}

function filterActivityTable(events, emptyText) {
  const rows = events.map((event) => [
    td(esc(fmtDate(event.at))),
    td(`<span class="mono small">${esc(filterServiceLabel(event.service))}</span>`),
    td(filterSeverityBadge(event.severity)),
    td(`<span class="small">${esc(event.message)}</span>`),
  ]);
  return table(['Fecha', 'Servicio', 'Nivel', 'Mensaje'], rows, emptyText);
}

async function renderFilters() {
  const data = await api('/api/v1/mail/filters');
  const programs = data.programs || [];
  const events = data.events || [];
  const byName = new Map(programs.map((program) => [program.name, program]));
  const antivirus = ['clamav', 'clamav-milter']
    .map((name) => byName.get(name))
    .filter(Boolean);
  const antispam = ['spamassassin', 'spamass-milter']
    .map((name) => byName.get(name))
    .filter(Boolean);
  const running = (list) => list.length > 0 && list.every((program) => program.service_status === 'active');
  const avEvents = events.filter((event) => event.kind === 'antivirus');
  const asEvents = events.filter((event) => event.kind === 'antispam');
  const detections = avEvents.filter((event) => event.severity === 'alert').length;
  const spamBlocks = asEvents.filter((event) => event.severity === 'warn' || event.severity === 'alert').length;
  const statusValue = (active) => `<div class="value small-value">${active ? badge('activo', 'ok') : badge('revisar', 'warn')}</div>`;

  $('#view').innerHTML = `
    <div class="grid cols-4">
      <div class="card stat"><div class="label">Antivirus</div>${statusValue(running(antivirus))}<div class="hint">ClamAV + milter SMTP</div></div>
      <div class="card stat"><div class="label">Antispam</div>${statusValue(running(antispam))}<div class="hint">SpamAssassin + milter SMTP</div></div>
      <div class="card stat"><div class="label">Detecciones</div><div class="value">${detections}</div><div class="hint">en los últimos eventos</div></div>
      <div class="card stat"><div class="label">Bloqueos de spam</div><div class="value">${spamBlocks}</div><div class="hint">mensajes rechazados o marcados</div></div>
    </div>
    <div class="card"><p class="muted small" style="margin:0">
      Postfix ejecuta los milters en el orden <span class="mono">SpamAssassin → ClamAV</span> y DKIM firma al final.
      ClamAV actualiza sus firmas con <span class="mono">clamav-freshclam</span> y SpamAssassin con
      <span class="mono">sa-update</span>. El análisis programado revisa <span class="mono">/home</span> y
      <span class="mono">/var/vmail</span> cada día.
    </p></div>
    ${sectionHead('Filtros de correo', '<button class="btn ghost" data-action="reload">Refrescar</button>')}
    <div class="grid cols-2">
      <div class="card">${sectionHead('Antivirus')}${filterComponentTable(antivirus, 'No se detectó ClamAV.')}</div>
      <div class="card">${sectionHead('Antispam')}${filterComponentTable(antispam, 'No se detectó SpamAssassin.')}</div>
    </div>
    ${sectionHead('Actividad de antivirus', '<span class="muted small">eventos recientes del journal</span>')}
    ${filterActivityTable(avEvents, 'Sin actividad de antivirus.')}
    ${sectionHead('Actividad de antispam', '<span class="muted small">eventos recientes del journal</span>')}
    ${filterActivityTable(asEvents, 'Sin actividad de antispam.')}`;
}

/* ---------------- AI agent ---------------- */

const AGENT_SEVERITY_LABELS = {
  critical: 'crítica',
  high: 'alta',
  medium: 'media',
  low: 'baja',
  info: 'información',
};

const AGENT_STATUS_LABELS = {
  open: 'abierta',
  acknowledged: 'revisada',
  ignored: 'ignorada',
  resolved: 'resuelta',
};

const AGENT_CATEGORY_LABELS = {
  security: 'seguridad',
  reliability: 'fiabilidad',
  maintenance: 'mantenimiento',
};

function agentSeverityBadge(severity) {
  const kind = severity === 'critical' || severity === 'high' ? 'bad' : severity === 'medium' ? 'warn' : 'info';
  return badge(AGENT_SEVERITY_LABELS[severity] || severity, kind);
}

function agentStatusBadge(status) {
  const kind = status === 'acknowledged' || status === 'resolved' ? 'ok' : status === 'ignored' ? '' : 'warn';
  return badge(AGENT_STATUS_LABELS[status] || status, kind);
}

async function renderAgent() {
  const data = await api('/api/v1/agent/findings?status=all&limit=200');
  const findings = data.findings || [];
  S.data.agentFindings = findings;
  const stats = data.stats || {};
  const last = data.last_run;
  const rows = findings.map((finding) => {
    const actions = [
      btn('Detalle', 'agent-detail', finding.id, 'tiny ghost'),
      finding.status === 'open'
        ? btn('Reconocer', 'agent-ack', finding.id, 'tiny')
        : btn('Reabrir', 'agent-reopen', finding.id, 'tiny ghost'),
      finding.status === 'ignored' ? '' : btn('Ignorar', 'agent-ignore', finding.id, 'tiny ghost'),
    ].filter(Boolean).join(' ');
    return [
      td(agentSeverityBadge(finding.severity)),
      td(`<span class="chip">${esc(T(AGENT_CATEGORY_LABELS[finding.category] || finding.category))}</span>`),
      td(`<div class="cell-title">${esc(finding.title)}</div><div class="cell-sub">${esc(finding.summary)}</div>`),
      td(agentStatusBadge(finding.status)),
      td(esc(fmtDate(finding.updated_at))),
      td(String(finding.occurrences)),
      td(actions, 'actions'),
    ];
  });
  const lastRun = last
    ? `${esc(fmtDate(last.finished_at))} · ${last.status === 'ok' ? badge('correcto', 'ok') : badge('error', 'bad')} · ${esc(last.findings)} hallazgos`
    : '<span class="muted">Sin ejecuciones todavía</span>';
  const lastSummary = last && last.summary
    ? `<p class="muted small">${esc(last.summary)}</p>`
    : '';

  $('#view').innerHTML = `
    <div class="grid cols-4">
      <div class="card stat"><div class="label">Críticas</div><div class="value">${stats.critical || 0}</div><div class="hint">requieren atención inmediata</div></div>
      <div class="card stat"><div class="label">Altas</div><div class="value">${stats.high || 0}</div><div class="hint">amenazas y errores graves</div></div>
      <div class="card stat"><div class="label">Abiertas</div><div class="value">${stats.open || 0}</div><div class="hint">sin revisar</div></div>
      <div class="card stat"><div class="label">Último análisis</div><div class="value small-value">${last ? esc(fmtDate(last.finished_at)) : '—'}</div><div class="hint">${last ? esc(last.model) : 'sin ejecuciones'}</div></div>
    </div>
    <div class="card"><p class="muted small" style="margin:0">
      El agente analiza el estado del nodo, los servicios, los certificados, las actualizaciones y el journal de correo.
      Solo detecta y recomienda; nunca ejecuta acciones. Las alertas altas y críticas se envían por email si
      <span class="mono">smtp_alert_to</span> está configurado.
    </p></div>
    ${sectionHead('Hallazgos', `<button class="btn primary" data-action="agent-run">Analizar ahora</button> <button class="btn ghost" data-action="agent-test-provider">Probar proveedor</button> <button class="btn ghost" data-action="reload">Actualizar</button>`)}
    <p class="muted small">${lastRun}</p>
    ${lastSummary}
    ${table(['Severidad', 'Categoría', 'Hallazgo', 'Estado', 'Actualizado', 'Ocurrencias', 'Acciones'], rows, 'Sin hallazgos. El sistema no presenta alertas conocidas.')}`;
}

/* ---------------- security ---------------- */

async function renderSecurity() {
  const [stats, eventsData] = await Promise.all([
    api('/api/v1/security/stats?hours=24'),
    api('/api/v1/security/auth-events?limit=200'),
  ]);
  const events = eventsData.events || [];
  const rows = events.map((event) => [
    td(esc(fmtDate(event.at))),
    td(`<strong>${esc(event.username)}</strong>`),
    td(`<span class="mono small">${esc(event.ip)}</span>`),
    td(event.outcome === 'success' ? badge('ok', 'ok') : event.outcome === 'blocked' ? badge('bloqueado', 'bad') : event.outcome === 'impersonation' ? badge('suplantación', 'info') : badge('fallo', 'warn')),
    td(esc(event.reason)),
    td(`<span class="muted small">${esc(event.user_agent)}</span>`),
  ]);
  $('#view').innerHTML = `
    <div class="grid cols-4">
      <div class="card stat"><div class="label">Fallos 24 h</div><div class="value">${stats.failures}</div><div class="hint">credenciales inválidas</div></div>
      <div class="card stat"><div class="label">Bloqueos</div><div class="value">${stats.blocked}</div><div class="hint">rate limit / lockout</div></div>
      <div class="card stat"><div class="label">Accesos OK</div><div class="value">${stats.successes}</div><div class="hint">sesiones creadas</div></div>
      <div class="card stat"><div class="label">IPs únicas</div><div class="value">${stats.unique_ips}</div><div class="hint">con intentos fallidos</div></div>
    </div>
    ${sectionHead('Eventos de autenticación', '<span class="muted small">también en /var/log/rynxcp/auth.log (fail2ban)</span>')}
    ${table(['Fecha', 'Usuario', 'IP', 'Resultado', 'Motivo', 'User-Agent'], rows, 'Sin eventos de autenticación.')}`;
}

/* ---------------- firewall ---------------- */

async function renderFirewall() {
  const data = await api('/api/v1/firewall');
  const fw = data.state;
  const ruleRows = fw.rules.map((rule) => [
    td(rule.spec.action === 'allow' ? badge('permitir', 'ok') : badge('denegar', 'bad')),
    td(`<span class="chip">${esc(rule.spec.proto)}</span>`),
    td(esc(rule.spec.port)),
    td(`<span class="mono small">${esc(rule.spec.source || '*')}</span>`),
    td(esc(rule.spec.comment || '—')),
    td(btn('Eliminar', 'firewall-rule-delete', rule.id, 'tiny danger'), 'actions'),
  ]);
  const blockedRows = fw.blocked.map((entry) => [
    td(`<span class="mono">${esc(entry.ip)}</span>`),
    td(esc(entry.reason)),
    td(badge(entry.source, entry.source === 'brute-force' ? 'warn' : entry.source === 'fail2ban' ? 'info' : '')),
    td(entry.source === 'fail2ban' ? '—' : esc(entry.expires_at ? fmtDate(entry.expires_at) : 'permanente')),
    td(btn('Quitar', 'firewall-unblock', entry.ip, 'tiny ghost'), 'actions'),
  ]);
  const whiteRows = fw.whitelist.map((ip) => [
    td(`<span class="mono">${esc(ip)}</span>`),
    td(btn('Quitar', 'firewall-whitelist-remove', ip, 'tiny ghost'), 'actions'),
  ]);
  $('#view').innerHTML = `
    <div class="grid cols-4">
      <div class="card stat"><div class="label">Cortafuegos</div><div class="value small-value">${fw.enabled ? badge('activo', 'ok') : badge('desactivado', 'warn')}</div><div class="hint">${esc(fw.backend)}</div></div>
      <div class="card stat"><div class="label">Baneadas</div><div class="value">${fw.blocked.length}</div><div class="hint">manual + fuerza bruta</div></div>
      <div class="card stat"><div class="label">Lista blanca</div><div class="value">${fw.whitelist.length}</div><div class="hint">prioridad máxima</div></div>
      <div class="card stat"><div class="label">SSH</div><div class="value">${esc(fw.ssh_port)}</div><div class="hint">siempre permitido</div></div>
    </div>
    <div class="card"><p class="muted small" style="margin:0">
      Las reglas se aplican en la tabla nftables aislada <span class="mono">inet rynxcp</span>.
      La lista blanca tiene prioridad sobre los baneos. El puerto SSH se permite siempre para evitar bloqueos.
      Los baneos automáticos duran 1 hora y se retiran solos.
    </p></div>
    ${sectionHead('Reglas', '<button class="btn primary" data-action="firewall-rule-new">Añadir regla</button>')}
    ${table(['Acción', 'Protocolo', 'Puerto', 'Origen', 'Comentario', ''], ruleRows, 'Sin reglas personalizadas.')}
    ${sectionHead('IPs baneadas', '<button class="btn primary" data-action="firewall-block-new">Banear IP</button>')}
    ${table(['IP', 'Motivo', 'Origen', 'Expira', ''], blockedRows, 'No hay IPs baneadas.')}
    ${sectionHead('Lista blanca', '<button class="btn primary" data-action="firewall-whitelist-new">Añadir IP</button>')}
    ${table(['IP / CIDR', ''], whiteRows, 'Sin direcciones privilegiadas.')}`;
}

function openFirewallRuleModal() {
  openModal({
    title: 'Nueva regla de cortafuegos',
    submitLabel: 'Aplicar',
    html: `<div class="form-grid">
      ${fSelect('action', 'Acción', [{ value: 'allow', label: 'Permitir' }, { value: 'deny', label: 'Denegar' }], { value: 'allow' })}
      ${fSelect('proto', 'Protocolo', ['tcp', 'udp', 'any'], { value: 'tcp' })}
      ${fInput('port', 'Puerto', { type: 'number', value: 8080, min: 1, max: 65535, required: true })}
      ${fInput('source', 'Origen (IP/CIDR)', { placeholder: 'opcional, ej. 10.0.0.0/8' })}
      ${fInput('comment', 'Comentario', { placeholder: 'motivo de la regla', full: true })}
    </div>`,
    onSubmit: async (form) => {
      await api('/api/v1/firewall/rules', {
        method: 'POST',
        body: {
          action: val(form, 'action'),
          proto: val(form, 'proto'),
          port: num(form, 'port', 0),
          source: val(form, 'source') || null,
          comment: val(form, 'comment'),
        },
      });
      toast('Regla aplicada');
      await refresh();
    },
  });
}

function openFirewallBlockModal() {
  openModal({
    title: 'Banear dirección IP',
    submitLabel: 'Banear',
    html: `<div class="form-grid">
      ${fInput('ip', 'IP o CIDR', { required: true, placeholder: '198.51.100.7' })}
      ${fSelect('duration', 'Duración', [{ value: '3600', label: '1 hora' }, { value: '86400', label: '24 horas' }, { value: '0', label: 'Permanente' }], { value: '3600' })}
      ${fInput('reason', 'Motivo', { placeholder: 'manual', full: true })}
    </div>`,
    onSubmit: async (form) => {
      await api('/api/v1/firewall/block', {
        method: 'POST',
        body: { ip: val(form, 'ip'), seconds: num(form, 'duration', 3600), reason: val(form, 'reason') || 'manual' },
      });
      toast('IP baneada');
      await refresh();
    },
  });
}

function openWhitelistModal() {
  openModal({
    title: 'Añadir a lista blanca',
    submitLabel: 'Añadir',
    html: `<div class="form-grid">${fInput('ip', 'IP o CIDR', { required: true, placeholder: '203.0.113.4', full: true })}</div>`,
    onSubmit: async (form) => {
      await api('/api/v1/firewall/whitelist', { method: 'POST', body: { ip: val(form, 'ip') } });
      toast('IP añadida a la lista blanca');
      await refresh();
    },
  });
}

/* ---------------- programs ---------------- */

async function renderPrograms() {
  await Promise.all([loadList('programs'), loadList('updates')]);
  const updates = S.data.updates;
  const security = updates.filter((u) => u.security).length;
  const updateRows = updates.map((update) => [
    td(`<span class="mono">${esc(update.package)}</span>`),
    td(esc(update.current_version || '—')),
    td(esc(update.candidate_version)),
    td(update.security ? badge('seguridad', 'bad') : badge('normal', '')),
  ]);
  const programRows = S.data.programs.map((program) => [
    td(`<div class="cell-title">${esc(program.name)}</div><div class="cell-sub">${esc(program.detail)}</div>`),
    td(`<span class="mono small">${esc(program.version)}</span>`),
    td(`<span class="chip">${esc(program.kind)}</span>`),
    td(program.status === 'installed' ? badge('instalado', 'ok') : badge('ausente', 'warn')),
    td(programServiceBadge(program)),
    td(programUnit(program) && program.status === 'installed' ? [
      programButton('program-restart', program.name, 'Reiniciar', '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>'),
      programButton('program-stop', program.name, 'Parar', '<rect x="6" y="6" width="12" height="12" rx="1"/>'),
    ].join(' ') : '', 'actions'),
  ]);
  $('#view').innerHTML = `
    <div class="grid cols-3">
      <div class="card stat"><div class="label">Actualizaciones</div><div class="value">${updates.length}</div><div class="hint">${security} de seguridad</div></div>
      <div class="card stat"><div class="label">Programas detectados</div><div class="value">${S.data.programs.length}</div><div class="hint">nginx, runtimes, DB, DNS, FTP, mail</div></div>
      <div class="card stat"><div class="label">Repositorio</div><div class="value small-value">apt</div><div class="hint">Debian / Ubuntu</div></div>
    </div>
    ${sectionHead('Actualizaciones disponibles', `<button class="btn primary" data-action="updates-apply" ${updates.length ? '' : 'disabled'}>Actualizar todo</button>`)}
    ${table(['Paquete', 'Actual', 'Disponible', 'Tipo'], updateRows, 'El sistema está actualizado.')}
    ${sectionHead('Software instalado', '<button class="btn ghost" data-action="reload">Refrescar</button>')}
    ${table(['Programa', 'Versión', 'Tipo', 'Estado'], programRows, 'No se detectó software.')}`;
}

/* ---------------- console ---------------- */

const CONSOLE_ACTIONS = [
  ['nginx_test', 'Validar configuración de Nginx'],
  ['nginx_reload', 'Recargar Nginx'],
  ['services', 'Listar servicios'],
  ['disk_usage', 'Uso de disco'],
  ['reconcile', 'Reconciliar todo el estado'],
  ['cert_renew', 'Renovar certificados'],
  ['backup_all', 'Crear backups de todas las cuentas'],
  ['php_reload', 'Recargar PHP-FPM'],
  ['app_restart', 'Reiniciar aplicación'],
  ['app_logs', 'Ver logs de aplicación'],
];

async function renderConsole() {
  await Promise.all([loadList('accounts'), loadList('apps')]);
  const phpVersions = await loadPhpVersions();
  const appOptions = S.data.apps.map((app) => ({
    value: `${app.spec.username}/${app.spec.name}`,
    label: `${app.spec.username}/${app.spec.name}`,
  }));
  $('#view').innerHTML = `
    <div class="card">
      <div class="section-head"><h2>Acción</h2>${badge('sin shell libre', 'info')}</div>
      <form id="console-form" class="form-grid" style="margin-top:16px">
        ${fSelect('action', 'Comando', CONSOLE_ACTIONS.map(([value, label]) => ({ value, label })), { value: 'services', full: true })}
        ${fSelect('php_version', 'Versión PHP (php_reload)', phpVersions.map((v) => ({ value: v, label: v })), { value: phpVersions[0] || '' })}
        ${fSelect('app', 'Aplicación (restart / logs)', appOptions.length ? appOptions : [{ value: '', label: '— sin aplicaciones —' }])}
        ${fInput('lines', 'Líneas de log', { type: 'number', value: 100, min: 10, max: 500 })}
        <div class="full row-inline"><button class="btn primary" type="submit">Ejecutar</button><span class="muted small">Toda acción queda registrada en la auditoría encadenada.</span></div>
      </form>
    </div>
    <div class="card">
      <div class="section-head"><h2>Salida</h2><span class="muted small">máx. 64 KiB</span></div>
      <pre id="console-output" class="console-out">${esc(S.consoleOutput || 'Listo. Elige una acción y pulsa Ejecutar.')}</pre>
    </div>`;

  $('#console-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const actionName = val(form, 'action');
    let action = { action: actionName };
    if (actionName === 'php_reload') action.version = val(form, 'php_version');
    if (actionName === 'app_restart' || actionName === 'app_logs') {
      const target = val(form, 'app');
      if (!target) throw new Error('Selecciona una aplicación');
      const [username, name] = target.split('/');
      action.username = username;
      action.name = name;
      if (actionName === 'app_logs') action.lines = num(form, 'lines', 100);
    }
    try {
      const result = await api('/api/v1/console', { method: 'POST', body: { action } });
      S.consoleOutput = result.output || '(sin salida)';
      const pre = $('#console-output');
      if (pre) pre.textContent = S.consoleOutput;
      toast(TF('{action} ejecutado', { action: T(result.action) }));
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

/* ---------------- helpers for new views ---------------- */

function fmtBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value >= 1024 * 1024 * 1024) return `${(value / 1024 / 1024 / 1024).toFixed(2)} GiB`;
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MiB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${value} B`;
}

function showOutput(title, text) {
  openModal({
    title,
    submitLabel: 'Cerrar',
    html: `<pre class="console-out">${esc(text)}</pre>`,
    onSubmit: async () => {},
  });
}

/* ---------------- wiring ---------------- */

window.RYNX_ON_LANG_CHANGE = (code) => {
  if (S.user) {
    persistUserLocale(code);
    refresh();
  } else {
    showLogin();
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(location.search);
  const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  S.resetToken = params.get('reset_token') || hash.get('reset_token') || null;

  $('#login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const data = await publicPost('/api/v1/auth/login', {
        username: val(form, 'username'),
        password: form.elements.password.value,
      });
      if (data && data.two_factor_required) {
        form.reset();
        showTwoFactor(data.email, data.challenge);
        return;
      }
      S.user = data.user;
      S.csrf = data.csrf_token;
      S.impersonatedBy = data.impersonated_by || null;
      form.reset();
      enterApp();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  $('#forgot-open').addEventListener('click', () => showLoginForm('forgot'));

  $('#twofa-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const data = await publicPost('/api/v1/auth/verify-2fa', {
        challenge: S.twoFactorChallenge,
        code: form.elements.code.value.trim(),
      });
      S.user = data.user;
      S.csrf = data.csrf_token;
      S.impersonatedBy = data.impersonated_by || null;
      S.twoFactorChallenge = null;
      form.reset();
      enterApp();
    } catch (err) {
      form.elements.code.value = '';
      form.elements.code.focus();
      toast(err.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  $('#twofa-cancel').addEventListener('click', () => {
    S.twoFactorChallenge = null;
    showLoginForm('login');
  });

  $('#forgot-cancel').addEventListener('click', () => showLoginForm('login'));

  $('#forgot-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await publicPost('/api/v1/auth/forgot-password', {
        email: toAsciiEmail(val(form, 'email')),
      });
      form.reset();
      showLoginForm('login');
      toast('Si el email existe, recibirás un enlace para restablecer la contraseña.');
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  $('#reset-cancel').addEventListener('click', () => {
    S.resetToken = null;
    if (location.search || location.hash) history.replaceState(null, '', location.pathname);
    showLoginForm('login');
  });

  $('#reset-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const password = form.elements.password.value;
    if (password !== form.elements.confirm.value) {
      toast('Las contraseñas no coinciden', 'error');
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await publicPost('/api/v1/auth/reset-password', {
        token: S.resetToken || '',
        password,
      });
      S.resetToken = null;
      if (location.search || location.hash) history.replaceState(null, '', location.pathname);
      form.reset();
      showLoginForm('login');
      toast('Contraseña actualizada; ya puedes iniciar sesión');
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      button.disabled = false;
    }
  });

  const stopImpersonation = $('#stop-impersonation');
  if (stopImpersonation) {
    stopImpersonation.addEventListener('click', async () => {
      try {
        const data = await api('/api/v1/auth/stop-impersonation', { method: 'POST' });
        S.user = data.user;
        S.csrf = data.csrf_token;
        S.impersonatedBy = data.impersonated_by || null;
        enterApp();
        toast('Sesión de administrador restaurada');
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  }

  const certAlertReview = $('#cert-alert-review');
  if (certAlertReview) {
    certAlertReview.addEventListener('click', () => navigate('ssl'));
  }

  setInterval(() => {
    if (S.user && S.current === 'monitor' && document.visibilityState === 'visible') {
      renderMonitor().catch(() => {});
    }
  }, 20000);

  $('#logout').addEventListener('click', async () => {
    try { await api('/api/v1/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
    showLogin();
  });

  $('#view').addEventListener('click', async (event) => {
    const target = event.target.closest('[data-action]');
    if (!target) return;
    try {
      await handleAction(target.dataset.action, target.dataset.id || '');
    } catch (err) {
      toast(err.message, 'error');
    }
  });

  boot();
});




