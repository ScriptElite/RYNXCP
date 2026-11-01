//! Deterministic renderers for every artifact owned by RYNXCP.
//!
//! Generated files carry a management marker. The daemon only ever deletes or
//! rewrites files inside its managed roots and only when they carry that
//! marker or were recorded in its state database.

use std::fmt::Write as _;
use std::path::Path;

use rynx_proto::{AppSpec, DnsRecordView, PhpPoolSpec, Runtime, TlsMode, WebsiteSpec};

pub const MARKER: &str = "managed-by: RYNXCP";

pub struct NginxContext<'a> {
    pub domain: &'a str,
    pub aliases: &'a [String],
    pub docroot: &'a str,
    pub runtime: &'a Runtime,
    pub app_port: Option<u16>,
    pub php_socket: Option<&'a str>,
    pub tls: &'a TlsMode,
    pub cert_dir: Option<&'a Path>,
    pub acme_root: &'a str,
    pub force_https: bool,
}

fn server_names(ctx: &NginxContext<'_>) -> String {
    let mut names = vec![ctx.domain.to_string()];
    for alias in ctx.aliases {
        if !names.iter().any(|n| n == alias) {
            names.push(alias.clone());
        }
    }
    names.join(" ")
}

fn proxy_location(port: u16) -> String {
    format!(
        "    location / {{\n\
         \x20       proxy_pass http://127.0.0.1:{port};\n\
         \x20       proxy_http_version 1.1;\n\
         \x20       proxy_set_header Host $host;\n\
         \x20       proxy_set_header X-Real-IP $remote_addr;\n\
         \x20       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
         \x20       proxy_set_header X-Forwarded-Proto $scheme;\n\
         \x20       proxy_set_header Upgrade $http_upgrade;\n\
         \x20       proxy_set_header Connection \"upgrade\";\n\
         \x20       proxy_read_timeout 300s;\n\
         \x20       proxy_send_timeout 300s;\n\
         \x20   }}\n"
    )
}

fn common_server_body(ctx: &NginxContext<'_>, out: &mut String) {
    let _ = writeln!(out, "    root {};", ctx.docroot);
    let _ = writeln!(out, "    disable_symlinks on;");
    let _ = writeln!(out, "    index index.php index.html index.htm;");
    let _ = writeln!(out, "    client_max_body_size 64m;");
    let _ = writeln!(out, "    server_tokens off;");
    let _ = writeln!(out, "    add_header X-Content-Type-Options nosniff always;");
    let _ = writeln!(out, "    add_header X-Frame-Options SAMEORIGIN always;");
    let _ = writeln!(
        out,
        "    add_header Referrer-Policy strict-origin-when-cross-origin always;"
    );
    let _ = writeln!(
        out,
        "    add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\" always;"
    );
    let _ = writeln!(
        out,
        "    add_header Content-Security-Policy \"frame-ancestors 'self'; object-src 'none'; base-uri 'self'\" always;"
    );
    let _ = writeln!(out, "    location ^~ /.well-known/acme-challenge/ {{");
    let _ = writeln!(out, "        root {};", ctx.acme_root);
    let _ = writeln!(out, "        default_type \"text/plain\";");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "    location ~ /\\.(?!well-known) {{ deny all; }}");
    let _ = writeln!(
        out,
        "    location = /favicon.ico {{ log_not_found off; access_log off; }}"
    );

    match ctx.runtime {
        Runtime::Static => {
            let _ = writeln!(out, "    location / {{ try_files $uri $uri/ =404; }}");
        }
        Runtime::Php { .. } => {
            let _ = writeln!(
                out,
                "    location / {{ try_files $uri $uri/ /index.php?$query_string; }}"
            );
            let socket = ctx.php_socket.unwrap_or("unix:/run/php/php-fpm.sock");
            let socket = if socket.starts_with("unix:") {
                socket.to_string()
            } else {
                format!("unix:{socket}")
            };
            let _ = writeln!(out, "    location ~ \\.php$ {{");
            let _ = writeln!(out, "        include snippets/fastcgi-php.conf;");
            let _ = writeln!(out, "        fastcgi_pass {socket};");
            let _ = writeln!(out, "    }}");
        }
        _ => {
            if let Some(port) = ctx.app_port {
                out.push_str(&proxy_location(port));
            } else {
                let _ = writeln!(out, "    location / {{ return 503; }}");
            }
        }
    }
}

/// Full Nginx virtual host for a website.
pub fn nginx_site(ctx: &NginxContext<'_>) -> String {
    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "# {MARKER}");
    let _ = writeln!(out, "# domain: {}", ctx.domain);
    let names = server_names(ctx);

    let tls_enabled =
        matches!(ctx.tls, TlsMode::LetsEncrypt | TlsMode::Manual) && ctx.cert_dir.is_some();

    let _ = writeln!(out, "server {{");
    let _ = writeln!(out, "    listen 80;");
    let _ = writeln!(out, "    listen [::]:80;");
    let _ = writeln!(out, "    server_name {names};");
    let _ = writeln!(
        out,
        "    access_log /var/log/nginx/{}.access.log;",
        ctx.domain
    );
    let _ = writeln!(
        out,
        "    error_log /var/log/nginx/{}.error.log;",
        ctx.domain
    );
    if tls_enabled && ctx.force_https {
        let _ = writeln!(out, "    location ^~ /.well-known/acme-challenge/ {{");
        let _ = writeln!(out, "        root {};", ctx.acme_root);
        let _ = writeln!(out, "        default_type \"text/plain\";");
        let _ = writeln!(out, "    }}");
        let _ = writeln!(
            out,
            "    location / {{ return 301 https://$host$request_uri; }}"
        );
    } else {
        common_server_body(ctx, &mut out);
    }
    let _ = writeln!(out, "}}\n");

    if tls_enabled {
        let cert_dir = ctx.cert_dir.expect("checked above").display();
        let _ = writeln!(out, "server {{");
        let _ = writeln!(out, "    listen 443 ssl;");
        let _ = writeln!(out, "    listen [::]:443 ssl;");
        let _ = writeln!(out, "    http2 on;");
        let _ = writeln!(out, "    server_name {names};");
        let _ = writeln!(out, "    ssl_certificate {cert_dir}/fullchain.pem;");
        let _ = writeln!(out, "    ssl_certificate_key {cert_dir}/privkey.pem;");
        let _ = writeln!(out, "    ssl_protocols TLSv1.2 TLSv1.3;");
        let _ = writeln!(out, "    ssl_prefer_server_ciphers off;");
        let _ = writeln!(out, "    ssl_session_cache shared:RYNX:10m;");
        let _ = writeln!(out, "    ssl_session_timeout 1d;");
        let _ = writeln!(out, "    ssl_session_tickets off;");
        if ctx.force_https {
            let _ = writeln!(
                out,
                "    add_header Strict-Transport-Security \"max-age=31536000\" always;"
            );
        }
        let _ = writeln!(
            out,
            "    access_log /var/log/nginx/{}.access.log;",
            ctx.domain
        );
        let _ = writeln!(
            out,
            "    error_log /var/log/nginx/{}.error.log;",
            ctx.domain
        );
        common_server_body(ctx, &mut out);
        let _ = writeln!(out, "}}");
    }

    out
}

/// Nginx vhost for the shared Roundcube webmail application.
pub fn webmail_site(
    domain: &str,
    aliases: &[String],
    cert_dir: Option<&Path>,
    acme_root: &str,
    webmail_root: &str,
    php_socket: &str,
) -> String {
    let mut names = vec![domain.to_string()];
    for alias in aliases {
        if !names.contains(alias) {
            names.push(alias.clone());
        }
    }
    let server_name = names.join(" ");
    let socket = if php_socket.starts_with("unix:") {
        php_socket.to_string()
    } else {
        format!("unix:{php_socket}")
    };
    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "# {MARKER}");
    let _ = writeln!(out, "# webmail: {domain}");
    out.push_str("server {\n");
    out.push_str("    listen 80;\n");
    let _ = writeln!(out, "    server_name {server_name};");
    let _ = writeln!(
        out,
        "    location ^~ /.well-known/acme-challenge/ {{ root {acme_root}; }}"
    );
    if cert_dir.is_some() {
        out.push_str("    location / { return 301 https://$host$request_uri; }\n");
    } else {
        webmail_location(&mut out, webmail_root, &socket);
    }
    out.push_str("}\n\n");

    if let Some(cert_dir) = cert_dir {
        let cert_dir = cert_dir.display();
        out.push_str("server {\n");
        out.push_str("    listen 443 ssl;\n");
        out.push_str("    http2 on;\n");
        let _ = writeln!(out, "    server_name {server_name};");
        let _ = writeln!(out, "    ssl_certificate {cert_dir}/fullchain.pem;");
        let _ = writeln!(out, "    ssl_certificate_key {cert_dir}/privkey.pem;");
        out.push_str("    ssl_protocols TLSv1.2 TLSv1.3;\n");
        out.push_str("    ssl_prefer_server_ciphers off;\n");
        out.push_str("    ssl_session_cache shared:RYNXWEBMAIL:10m;\n");
        out.push_str("    ssl_session_timeout 1d;\n");
        out.push_str("    ssl_session_tickets off;\n");
        out.push_str("    add_header Strict-Transport-Security \"max-age=31536000\" always;\n");
        out.push_str("    add_header X-Content-Type-Options \"nosniff\" always;\n");
        out.push_str("    add_header X-Frame-Options \"SAMEORIGIN\" always;\n");
        out.push_str(
            "    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n",
        );
        let _ = writeln!(out, "    access_log /var/log/nginx/{domain}.access.log;");
        let _ = writeln!(out, "    error_log /var/log/nginx/{domain}.error.log;");
        webmail_location(&mut out, webmail_root, &socket);
        out.push_str("}\n");
    }
    out
}

fn webmail_location(out: &mut String, webmail_root: &str, socket: &str) {
    let _ = writeln!(out, "    root {webmail_root};");
    out.push_str("    index index.php;\n");
    out.push_str("    client_max_body_size 32m;\n");
    out.push_str("    location ~ /\\.(?!well-known) { deny all; }\n");
    out.push_str("    location ~ ^/(config|temp|logs|SQL|bin|vendor)/ { deny all; }\n");
    out.push_str("    location / { try_files $uri $uri/ /index.php?$query_string; }\n");
    out.push_str("    location ~ [^/]\\.php(/|$) {\n");
    out.push_str("        include snippets/fastcgi-php.conf;\n");
    let _ = writeln!(out, "        fastcgi_pass {socket};");
    out.push_str("    }\n");
}

/// FPM pool for a hosting account. One process pool per account.
pub fn php_fpm_pool(spec: &PhpPoolSpec, socket: &str, home: &str) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "; {MARKER}");
    let _ = writeln!(out, "[global]");
    let _ = writeln!(
        out,
        "pid = /run/php/php{}-fpm-{}.pid",
        spec.version, spec.username
    );
    let _ = writeln!(
        out,
        "error_log = /var/log/php{}-fpm-{}.log",
        spec.version, spec.username
    );
    let _ = writeln!(out, "daemonize = no");
    let _ = writeln!(out, "[rynx-{}]", spec.username);
    let _ = writeln!(out, "user = {}", spec.username);
    let _ = writeln!(out, "group = {}", spec.username);
    let _ = writeln!(out, "listen = {socket}");
    let _ = writeln!(out, "listen.owner = www-data");
    let _ = writeln!(out, "listen.group = www-data");
    let _ = writeln!(out, "listen.mode = 0660");
    let _ = writeln!(out, "pm = {}", spec.process_manager.as_str());

    let children = spec.max_children.max(1);
    match spec.process_manager {
        rynx_proto::PhpProcessManager::Dynamic => {
            let start = (children / 2).max(1);
            let min_spare = (children / 4).max(1);
            let max_spare = (children / 2).max(min_spare + 1).min(children);
            let _ = writeln!(out, "pm.max_children = {children}");
            let _ = writeln!(out, "pm.start_servers = {start}");
            let _ = writeln!(out, "pm.min_spare_servers = {min_spare}");
            let _ = writeln!(out, "pm.max_spare_servers = {max_spare}");
        }
        rynx_proto::PhpProcessManager::Ondemand => {
            let _ = writeln!(out, "pm.max_children = {children}");
            let _ = writeln!(out, "pm.process_idle_timeout = 10s");
        }
        rynx_proto::PhpProcessManager::Static => {
            let _ = writeln!(out, "pm.max_children = {children}");
        }
    }

    let _ = writeln!(out, "pm.max_requests = 500");
    let _ = writeln!(out, "chdir = {home}");
    let _ = writeln!(out, "catch_workers_output = yes");
    let _ = writeln!(out, "decorate_workers_output = no");
    let _ = writeln!(out, "clear_env = yes");
    let _ = writeln!(out, "security.limit_extensions = .php");
    let sessions = format!("{}/{}", crate::paths::PHP_SESSION_ROOT, spec.username);
    let _ = writeln!(
        out,
        "php_admin_value[open_basedir] = {home}/:/tmp/:/usr/share/php/:{sessions}/"
    );
    let _ = writeln!(
        out,
        "php_admin_value[memory_limit] = {}M",
        spec.memory_limit_mb
    );
    let _ = writeln!(
        out,
        "php_admin_value[upload_max_filesize] = {}M",
        spec.upload_max_mb
    );
    let _ = writeln!(
        out,
        "php_admin_value[post_max_size] = {}M",
        spec.upload_max_mb.saturating_add(2)
    );
    let _ = writeln!(out, "php_admin_value[session.save_path] = {sessions}");
    let _ = writeln!(
        out,
        "php_admin_value[error_log] = {home}/logs/php-error.log"
    );
    let _ = writeln!(out, "php_admin_flag[log_errors] = on");
    let _ = writeln!(out, "php_admin_flag[display_errors] = off");
    let _ = writeln!(out, "php_admin_flag[expose_php] = off");
    let _ = writeln!(
        out,
        "php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
    );
    out
}

fn systemd_escape_arg(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".into();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:=@+".contains(c))
    {
        return value.to_string();
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// systemd unit for a managed application (Node, Python, Ruby, Java, .NET, Go).
pub fn systemd_unit(app: &AppSpec, working_dir: &str, env_file: &str, uid: u32) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "# {MARKER}");
    let _ = writeln!(
        out,
        "[Unit]\nDescription=RYNXCP {engine} application {user}/{name}\nAfter=network-online.target\nWants=network-online.target\n",
        engine = app.runtime.engine(),
        user = app.username,
        name = app.name
    );
    let _ = writeln!(out, "[Service]");
    let _ = writeln!(out, "Type=simple");
    let _ = writeln!(out, "User={}", app.username);
    let _ = writeln!(out, "Group={}", app.username);
    let _ = writeln!(out, "Slice=user-{uid}.slice");
    let _ = writeln!(out, "WorkingDirectory={working_dir}");
    let _ = writeln!(out, "EnvironmentFile=-{env_file}");
    let _ = writeln!(out, "Environment=PORT={}", app.port);
    let _ = writeln!(out, "Environment=HOST=127.0.0.1");

    let (program, args) = match &app.runtime {
        Runtime::Go => (format!("{working_dir}/{}", app.command), &app.args),
        _ => (app.command.clone(), &app.args),
    };
    let mut exec = format!("ExecStart={}", systemd_escape_arg(&program));
    for arg in args {
        exec.push(' ');
        exec.push_str(&systemd_escape_arg(arg));
    }
    let _ = writeln!(out, "{exec}");
    let _ = writeln!(out, "Restart=on-failure");
    let _ = writeln!(out, "RestartSec=3");
    let _ = writeln!(out, "KillSignal=SIGTERM");
    let _ = writeln!(out, "TimeoutStopSec=20");
    let _ = writeln!(out, "NoNewPrivileges=true");
    let _ = writeln!(out, "PrivateTmp=true");
    let _ = writeln!(out, "ProtectSystem=full");
    let _ = writeln!(out, "ProtectKernelTunables=true");
    let _ = writeln!(out, "ProtectControlGroups=true");
    let _ = writeln!(out, "RestrictSUIDSGID=true");
    let _ = writeln!(out, "LockPersonality=true");
    let _ = writeln!(out, "ReadWritePaths={working_dir}");
    let _ = writeln!(out, "\n[Install]\nWantedBy=multi-user.target");
    out
}

pub fn app_env_file(app: &AppSpec) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# {MARKER}");
    for (key, value) in &app.env {
        let _ = writeln!(out, "{key}={}", shell_quote_value(value));
    }
    out
}

fn shell_quote_value(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:@%+".contains(c))
    {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Initial welcome page for a newly created Static or PHP site.
pub fn welcome_page(locale: &str, domain: &str) -> String {
    let code = match locale {
        "es" | "en" | "pt" | "fr" | "ar" | "ru" | "zh" | "ja" | "it" | "de" => locale,
        _ => "en",
    };
    let (title, message, hint) = match code {
        "es" => (
            "Sitio publicado",
            "¡Bienvenido! Tu sitio ya está en línea.",
            "Sube tus archivos a la carpeta del sitio para reemplazar esta página.",
        ),
        "pt" => (
            "Site publicado",
            "Bem-vindo! Seu site está no ar.",
            "Envie seus arquivos para a pasta do site para substituir esta página.",
        ),
        "fr" => (
            "Site publié",
            "Bienvenue ! Votre site est en ligne.",
            "Téléversez vos fichiers dans le dossier du site pour remplacer cette page.",
        ),
        "ar" => (
            "تم نشر الموقع",
            "مرحبًا! موقعك الآن على الإنترنت.",
            "ارفع ملفاتك إلى مجلد الموقع لاستبدال هذه الصفحة.",
        ),
        "ru" => (
            "Сайт опубликован",
            "Добро пожаловать! Ваш сайт уже в сети.",
            "Загрузите файлы в папку сайта, чтобы заменить эту страницу.",
        ),
        "zh" => (
            "网站已发布",
            "欢迎！你的网站已经上线。",
            "将文件上传到网站目录即可替换此页面。",
        ),
        "ja" => (
            "サイトを公開しました",
            "ようこそ！サイトは公開中です。",
            "サイトのフォルダにファイルをアップロードすると、このページを置き換えられます。",
        ),
        "it" => (
            "Sito pubblicato",
            "Benvenuto! Il tuo sito è online.",
            "Carica i file nella cartella del sito per sostituire questa pagina.",
        ),
        "de" => (
            "Website veröffentlicht",
            "Willkommen! Deine Website ist online.",
            "Lade deine Dateien in den Website-Ordner hoch, um diese Seite zu ersetzen.",
        ),
        _ => (
            "Site published",
            "Welcome! Your site is online.",
            "Upload your files to the site folder to replace this page.",
        ),
    };
    let mut out = String::with_capacity(2048);
    out.push_str("<!doctype html>\n");
    let _ = writeln!(
        out,
        "<html lang=\"{code}\"{}>",
        if code == "ar" { " dir=\"rtl\"" } else { "" }
    );
    out.push_str("<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    let _ = writeln!(
        out,
        "<title>{} · {}</title>",
        escape_html(title),
        escape_html(domain)
    );
    out.push_str("<style>\n");
    out.push_str(":root { color-scheme: dark; --accent: #57e6a1; }\n");
    out.push_str("* { box-sizing: border-box; }\n");
    out.push_str("body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #070a0f; color: #e6edf4; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; }\n");
    out.push_str("main { width: min(640px, calc(100% - 32px)); padding: 32px; border: 1px solid #1e2b3a; border-radius: 16px; background: #0e141c; }\n");
    out.push_str(".kicker { color: var(--accent); text-transform: uppercase; letter-spacing: .14em; font-size: 12px; }\n");
    out.push_str("h1 { margin: .35em 0 .5em; font-size: clamp(28px, 6vw, 44px); }\n");
    out.push_str("p { line-height: 1.6; }\n");
    out.push_str("code { color: var(--accent); word-break: break-all; }\n");
    out.push_str(".hint { color: #8ea3b8; font-size: 14px; }\n");
    out.push_str("</style>\n</head>\n<body>\n<main>\n");
    out.push_str("<p class=\"kicker\">RYNXCP</p>\n");
    let _ = writeln!(out, "<h1>{}</h1>", escape_html(title));
    let _ = writeln!(out, "<p>{}</p>", escape_html(message));
    let _ = writeln!(out, "<p><code>{}</code></p>", escape_html(domain));
    let _ = writeln!(out, "<p class=\"hint\">{}</p>", escape_html(hint));
    out.push_str("</main>\n</body>\n</html>\n");
    out
}

pub fn nginx_filename(domain: &str) -> String {
    format!("{domain}.conf")
}

pub fn php_pool_filename(username: &str) -> String {
    format!("rynx-{username}.conf")
}

pub fn app_env_filename(username: &str, app: &str) -> String {
    format!("{username}-{app}.env")
}

pub fn website_docroot(spec: &WebsiteSpec, home: &str) -> String {
    format!("{home}/{}", spec.docroot.trim_matches('/'))
}

fn zone_fqdn(value: &str) -> String {
    if value.ends_with('.') {
        value.to_string()
    } else {
        format!("{value}.")
    }
}

fn txt_chunks(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return "\"\"".into();
    }
    let mut parts = Vec::new();
    for chunk in chars.chunks(255) {
        let text: String = chunk.iter().collect();
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        parts.push(format!("\"{escaped}\""));
    }
    parts.join(" ")
}

/// Render a BIND zone file. The SOA and NS records are derived from the
/// configured public nameservers; every other record comes from the state DB.
pub fn bind_zone(
    domain: &str,
    records: &[DnsRecordView],
    nameservers: &[String],
    serial: u32,
    default_ttl: u32,
) -> String {
    let effective_nameservers: Vec<String> = if nameservers.is_empty() {
        vec![format!("ns1.{domain}"), format!("ns2.{domain}")]
    } else {
        nameservers.to_vec()
    };
    let primary_ns = effective_nameservers
        .first()
        .cloned()
        .unwrap_or_else(|| format!("ns1.{domain}"));
    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "; {MARKER}");
    let _ = writeln!(out, "$TTL {default_ttl}");
    let _ = writeln!(
        out,
        "@ IN SOA {} hostmaster.{} (",
        zone_fqdn(&primary_ns),
        zone_fqdn(domain)
    );
    let _ = writeln!(out, "    {serial} ; serial");
    let _ = writeln!(out, "    3600 ; refresh");
    let _ = writeln!(out, "    900 ; retry");
    let _ = writeln!(out, "    1209600 ; expire");
    let _ = writeln!(out, "    300 ; minimum");
    let _ = writeln!(out, ")");
    for ns in &effective_nameservers {
        let _ = writeln!(out, "@ IN NS {}", zone_fqdn(ns));
    }

    let mut sorted: Vec<&DnsRecordView> = records.iter().collect();
    sorted.sort_by(|a, b| {
        a.spec
            .name
            .cmp(&b.spec.name)
            .then_with(|| a.spec.rtype.cmp(&b.spec.rtype))
            .then_with(|| a.spec.value.cmp(&b.spec.value))
    });

    for record in sorted {
        let owner = record.spec.name.as_str();
        let ttl = record.spec.ttl.max(60);
        let value = &record.spec.value;
        match record.spec.rtype.as_str() {
            "MX" => {
                let _ = writeln!(
                    out,
                    "{owner} {ttl} IN MX {} {}",
                    record.spec.priority.unwrap_or(10),
                    zone_fqdn(value)
                );
            }
            "CNAME" | "NS" => {
                let _ = writeln!(
                    out,
                    "{owner} {ttl} IN {} {}",
                    record.spec.rtype,
                    zone_fqdn(value)
                );
            }
            "TXT" => {
                let _ = writeln!(out, "{owner} {ttl} IN TXT {}", txt_chunks(value));
            }
            "SRV" => {
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() == 4 {
                    let _ = writeln!(
                        out,
                        "{owner} {ttl} IN SRV {} {} {} {}",
                        parts[0],
                        parts[1],
                        parts[2],
                        zone_fqdn(parts[3])
                    );
                }
            }
            "CAA" => {
                let _ = writeln!(out, "{owner} {ttl} IN CAA {value}");
            }
            "A" | "AAAA" => {
                let _ = writeln!(out, "{owner} {ttl} IN {} {value}", record.spec.rtype);
            }
            _ => {}
        }
    }
    out
}

pub fn dkim_txt_record(public_pem: &str) -> String {
    let body: String = public_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    format!(
        "v=DKIM1; k=rsa; p={}",
        body.replace(char::is_whitespace, "")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rynx_proto::{PhpProcessManager, Runtime};
    use std::collections::BTreeMap;

    fn ctx<'a>(tls: &'a TlsMode, cert: Option<&'a Path>) -> NginxContext<'a> {
        NginxContext {
            domain: "example.com",
            aliases: &[],
            docroot: "/home/acme/public_html",
            runtime: &Runtime::Static,
            app_port: None,
            php_socket: None,
            tls,
            cert_dir: cert,
            acme_root: "/var/www/_acme",
            force_https: true,
        }
    }

    #[test]
    fn bind_zone_defaults_nameservers_when_unset() {
        let zone = bind_zone("example.com", &[], &[], 42, 300);
        assert!(zone.starts_with("; managed-by: RYNXCP"));
        assert!(zone.contains("@ IN SOA ns1.example.com."));
        assert!(zone.contains("@ IN NS ns1.example.com."));
        assert!(zone.contains("@ IN NS ns2.example.com."));
    }

    #[test]
    fn static_site_has_no_php_handler() {
        let tls = TlsMode::Disabled;
        let conf = nginx_site(&ctx(&tls, None));
        assert!(conf.contains("server_name example.com;"));
        assert!(!conf.contains("fastcgi_pass"));
        assert!(conf.contains(MARKER));
        assert!(!conf.contains("listen 443"));
    }

    #[test]
    fn php_site_does_not_duplicate_fastcgi_try_files() {
        let rt = Runtime::Php {
            version: "8.5".into(),
        };
        let tls = TlsMode::Disabled;
        let mut c = ctx(&tls, None);
        c.runtime = &rt;
        let conf = nginx_site(&c);
        assert!(conf.contains("include snippets/fastcgi-php.conf;"));
        assert!(!conf.contains("try_files $uri =404;"));
    }

    #[test]
    fn welcome_page_is_localized() {
        let es = welcome_page("es", "example.com");
        assert!(es.contains("Bienvenido"));
        assert!(es.contains("example.com"));
        assert!(welcome_page("en", "example.com").contains("Welcome"));
        assert!(welcome_page("ar", "example.com").contains("dir=\"rtl\""));
        assert!(welcome_page("xx", "example.com").contains("Welcome"));
    }

    #[test]
    fn tls_site_redirects_and_uses_cert() {
        let tls = TlsMode::LetsEncrypt;
        let cert = Path::new("/etc/letsencrypt/live/example.com");
        let conf = nginx_site(&ctx(&tls, Some(cert)));
        assert!(conf.contains("listen 443 ssl;"));
        assert!(conf.contains("return 301 https://$host$request_uri;"));
        assert!(conf.contains("fullchain.pem"));
        assert!(conf.contains("Strict-Transport-Security"));
    }

    #[test]
    fn tls_site_can_serve_http_without_redirect() {
        let tls = TlsMode::LetsEncrypt;
        let cert = Path::new("/etc/letsencrypt/live/example.com");
        let mut c = ctx(&tls, Some(cert));
        c.force_https = false;
        let conf = nginx_site(&c);
        assert!(conf.contains("listen 443 ssl;"));
        assert!(conf.contains("/.well-known/acme-challenge/"));
        assert!(!conf.contains("return 301 https://$host$request_uri;"));
        assert!(!conf.contains("Strict-Transport-Security"));
    }

    #[test]
    fn managed_site_proxies_to_loopback() {
        let rt = Runtime::Node {
            version: "22".into(),
        };
        let tls = TlsMode::Disabled;
        let mut c = ctx(&tls, None);
        c.runtime = &rt;
        c.app_port = Some(4100);
        let conf = nginx_site(&c);
        assert!(conf.contains("proxy_pass http://127.0.0.1:4100;"));
        assert!(!conf.contains("fastcgi_pass"));
    }

    #[test]
    fn php_pool_restricts_functions() {
        let spec = PhpPoolSpec {
            username: "acme".into(),
            version: "8.3".into(),
            process_manager: PhpProcessManager::Dynamic,
            max_children: 8,
            memory_limit_mb: 256,
            upload_max_mb: 64,
            enabled: true,
        };
        let conf = php_fpm_pool(&spec, "/run/php/php8.3-fpm-acme.sock", "/home/acme");
        assert!(conf.contains("user = acme"));
        assert!(conf.contains("open_basedir"));
        assert!(conf.contains("disable_functions"));
        assert!(conf.contains("max_children = 8"));
    }

    #[test]
    fn systemd_unit_quotes_arguments() {
        let app = AppSpec {
            username: "acme".into(),
            name: "api".into(),
            runtime: Runtime::Python {
                version: "3.12".into(),
            },
            port: 4100,
            entrypoint: "app.py".into(),
            command: "gunicorn".into(),
            args: vec!["app:app".into(), "--bind=127.0.0.1:4100".into()],
            env: BTreeMap::new(),
            enabled: true,
        };
        let unit = systemd_unit(
            &app,
            "/home/acme/apps/api",
            "/etc/rynxcp/apps/acme-api.env",
            2000,
        );
        assert!(unit.contains("User=acme"));
        assert!(unit.contains("ExecStart=gunicorn app:app --bind=127.0.0.1:4100"));
        assert!(unit.contains("NoNewPrivileges=true"));
    }

    #[test]
    fn webmail_vhost_has_php_acme_and_tls() {
        let conf = webmail_site(
            "webmail.example.com",
            &["mail.example.com".into(), "imap.example.com".into()],
            Some(Path::new("/etc/letsencrypt/live/webmail.example.com")),
            "/var/www/_acme",
            "/usr/share/roundcube",
            "/run/php/php8.5-fpm.sock",
        );
        assert!(conf.contains("server_name webmail.example.com mail.example.com imap.example.com;"));
        assert!(conf.contains("location ^~ /.well-known/acme-challenge/"));
        assert!(conf
            .contains("ssl_certificate /etc/letsencrypt/live/webmail.example.com/fullchain.pem;"));
        assert!(conf.contains("fastcgi_pass unix:/run/php/php8.5-fpm.sock;"));
        assert!(conf.contains("location ~ [^/]\\.php(/|$)"));
        assert!(conf.contains("root /usr/share/roundcube;"));
        assert!(conf.contains("config|temp|logs"));
    }
}
