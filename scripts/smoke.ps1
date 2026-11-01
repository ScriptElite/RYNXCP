#!/usr/bin/env pwsh
# End-to-end smoke test in simulation mode. Requires: cargo build --workspace
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

$dataDir = Join-Path $root 'data'
if (Test-Path $dataDir) { Remove-Item -Recurse -Force $dataDir }
Get-Process rynxd, rynx-api -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 400

$logs = Join-Path $env:TEMP 'rynx-smoke'
if (Test-Path $logs) { Remove-Item -Recurse -Force $logs }
New-Item -ItemType Directory -Force -Path $logs | Out-Null

function Start-RynxProcess([string]$exe, [string]$name) {
    $out = Join-Path $logs "$name.out"
    $err = Join-Path $logs "$name.err"
    $process = Start-Process -FilePath (Join-Path $root $exe) `
        -ArgumentList '--config', "$name.toml" `
        -WorkingDirectory $root `
        -RedirectStandardOutput $out `
        -RedirectStandardError $err `
        -PassThru
    Start-Sleep -Milliseconds 1500
    if ($process.HasExited) {
        Write-Host "--- $name stderr ---"
        Get-Content $err -ErrorAction SilentlyContinue
        throw "$name exited unexpectedly"
    }
    return $process
}

$daemon = Start-RynxProcess 'target\debug\rynxd.exe' 'rynxd'
$api = $null
try {
    & (Join-Path $root 'target\debug\rynxctl.exe') --config rynx-api.toml admin create admin `
        --email admin@example.com --password 'Sup3r-Secret-Pass' --role owner | Out-Null

    $api = Start-RynxProcess 'target\debug\rynx-api.exe' 'rynx-api'

    $base = 'http://127.0.0.1:8080'
    $login = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method Post `
        -ContentType 'application/json' `
        -Body (@{ username = 'admin'; password = 'Sup3r-Secret-Pass' } | ConvertTo-Json) `
        -SessionVariable sess
    if (-not $login.csrf_token) { throw 'login did not return a CSRF token' }
    $headers = @{ 'x-csrf-token' = $login.csrf_token }

    function PostJson([string]$path, $body) {
        Invoke-RestMethod -Uri "$base$path" -Method Post -WebSession $sess -Headers $headers `
            -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 12)
    }

    function RequestJson([string]$method, [string]$path, $body = $null) {
        $params = @{ Uri = "$base$path"; Method = $method; WebSession = $sess; Headers = $headers }
        if ($null -ne $body) {
            $params.ContentType = 'application/json'
            $params.Body = ($body | ConvertTo-Json -Depth 12)
        }
        Invoke-RestMethod @params
    }

    function PackageBody($pkg) {
        @{
            name = [string]$pkg.name
            account_mb = [int]$pkg.account_mb
            bandwidth_mb = [int]$pkg.bandwidth_mb
            backups = [int]$pkg.backups
            incremental_backup = [bool]$pkg.incremental_backup
            web_domains = [int]$pkg.web_domains
            web_aliases = [int]$pkg.web_aliases
            web_backend = [string]$pkg.web_backend
            nginx_template = [string]$pkg.nginx_template
            dns_template = [string]$pkg.dns_template
            dns_zones = [int]$pkg.dns_zones
            dns_records = [int]$pkg.dns_records
            nameservers = @($pkg.nameservers)
            mail_domains = [int]$pkg.mail_domains
            mail_accounts = [int]$pkg.mail_accounts
            mail_rate_limit = [int]$pkg.mail_rate_limit
            databases = [int]$pkg.databases
            system_databases = [int]$pkg.system_databases
        }
    }

    function ExpectStatus([int]$expected, [scriptblock]$action) {
        try {
            & $action | Out-Null
            throw "expected HTTP $expected but request succeeded"
        } catch {
            $response = $_.Exception.Response
            $actual = if ($null -eq $response) { 0 } else { [int]$response.StatusCode }
            if ($actual -ne $expected) {
                throw "expected HTTP $expected, got ${actual}: $($_.Exception.Message)"
            }
        }
    }

    $page = Invoke-WebRequest -Uri "$base/" -UseBasicParsing
    if ($page.StatusCode -ne 200 -or $page.Content -notmatch 'RYNXCP') { throw 'web UI was not served' }
    $scriptJs = Invoke-WebRequest -Uri "$base/app.js" -UseBasicParsing
    if ($scriptJs.StatusCode -ne 200) { throw 'app.js was not served' }

    $null = RequestJson 'PUT' '/api/v1/auth/locale' @{ locale = 'fr' }
    if ((RequestJson 'GET' '/api/v1/auth/me').user.locale -ne 'fr') {
        throw 'the user locale was not persisted'
    }
    $null = RequestJson 'PUT' '/api/v1/auth/locale' @{ locale = 'es' }
    $phpVersions = RequestJson 'GET' '/api/v1/php/versions'
    if ($phpVersions.kind -ne 'php_versions' -or $phpVersions.versions -notcontains '8.5') {
        throw 'installed PHP versions are missing'
    }
    $seedPackages = @(RequestJson 'GET' '/api/v1/packages')
    if ($seedPackages.Count -lt 1 -or -not $seedPackages[0].is_default) {
        throw 'the default package was not seeded'
    }
    $seedPackage = $seedPackages[0]

    Write-Host '==> accounts, apps, websites'
    $account = PostJson '/api/v1/accounts' @{
        username = 'acme'; email = 'acme@example.com'; disk_limit_mb = 2048
        php_version = '8.3'; enabled = $true; ssh_enabled = $true
        package_id = $seedPackage.id; web_backend = 'php'
        panel_access = $true; panel_role = 'operator'
    }
    if ($account.account.kind -ne 'account') { throw 'unexpected account response' }
    if (-not $account.package -or $account.package.web_backend -ne 'php') {
        throw 'the account package assignment failed'
    }
    $assignment = @(RequestJson 'GET' '/api/v1/packages/assignments') |
        Where-Object { $_.account -eq 'acme' }
    if (-not $assignment -or $assignment.package_id -ne $seedPackage.id) {
        throw 'the account package assignment was not stored'
    }
    $updatedBackend = RequestJson 'PATCH' '/api/v1/packages/assignments/acme' @{ web_backend = 'node' }
    if ($updatedBackend.web_backend -ne 'node') { throw 'the account backend override failed' }

    Write-Host '==> SSH access'
    if (-not $account.panel_password) { throw 'panel access password missing' }
    $acmeLogin = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method Post `
        -ContentType 'application/json' -SessionVariable acmeSess `
        -Body (@{ username = 'acme'; password = $account.panel_password } | ConvertTo-Json)
    $acmeHeaders = @{ 'x-csrf-token' = $acmeLogin.csrf_token }
    $acmeMe = Invoke-RestMethod -Uri "$base/api/v1/auth/me" -WebSession $acmeSess
    if (-not $acmeMe.ssh_enabled) { throw 'scoped user did not receive SSH access' }
    $sshStatus = Invoke-RestMethod -Uri "$base/api/v1/ssh" -WebSession $acmeSess -Headers $acmeHeaders
    if ($sshStatus.username -ne 'acme') { throw 'SSH status has the wrong account' }
    $sshKey = 'ssh-ed25519 ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('smoke-key')) + ' smoke@test'
    $null = Invoke-RestMethod -Uri "$base/api/v1/ssh/keys" -Method Post -WebSession $acmeSess `
        -Headers $acmeHeaders -ContentType 'application/json' -Body (@{ key = $sshKey } | ConvertTo-Json)
    $sshStatus = Invoke-RestMethod -Uri "$base/api/v1/ssh" -WebSession $acmeSess -Headers $acmeHeaders
    if (@($sshStatus.keys) -notcontains $sshKey) { throw 'SSH key was not stored' }
    $null = Invoke-RestMethod -Uri "$base/api/v1/ssh/keys" -Method Delete -WebSession $acmeSess `
        -Headers $acmeHeaders -ContentType 'application/json' -Body (@{ key = $sshKey } | ConvertTo-Json)
    $sshStatus = Invoke-RestMethod -Uri "$base/api/v1/ssh" -WebSession $acmeSess -Headers $acmeHeaders
    if (@($sshStatus.keys) -contains $sshKey) { throw 'SSH key was not removed' }

    $app = PostJson '/api/v1/apps' @{
        username = 'acme'; name = 'api'; runtime = @{ engine = 'node'; version = '22' }
        port = 4100; entrypoint = 'server.js'; command = 'node'
        args = @('server.js'); env = @{ NODE_ENV = 'production' }; enabled = $true
    }
    if ($app.kind -ne 'app') { throw 'unexpected app response' }

    $site = PostJson '/api/v1/websites' @{
        domain = 'example.com'; username = 'acme'; aliases = @('www.example.com')
        runtime = @{ engine = 'node'; version = '22' }; app = 'api'
        docroot = 'public_html'; tls = 'disabled'; enabled = $true
    }
    if ($site.kind -ne 'website') { throw 'unexpected website response' }

    $siteConf = Join-Path $root 'data/daemon/sandbox/nginx/sites-available/example.com.conf'
    if (-not (Test-Path $siteConf)) { throw 'nginx site was not rendered' }
    if (-not (Select-String -Path $siteConf -Pattern 'proxy_pass http://127.0.0.1:4100' -Quiet)) {
        throw 'node site does not proxy to the application port'
    }

    Write-Host '==> php pool auto-provisioning'
    $phpSite = PostJson '/api/v1/websites' @{
        domain = 'php.example.com'; username = 'acme'; aliases = @()
        runtime = @{ engine = 'php'; version = '8.3' }; app = $null
        docroot = 'public_html'; tls = 'disabled'; enabled = $true
    }
    if ($phpSite.kind -ne 'website') { throw 'unexpected php website response' }
    $phpConf = Join-Path $root 'data/daemon/sandbox/nginx/sites-available/php.example.com.conf'
    if (-not (Select-String -Path $phpConf -Pattern 'fastcgi_pass unix:' -Quiet)) {
        throw 'php site does not use fastcgi'
    }
    $poolConf = Join-Path $root 'data/daemon/sandbox/php/8.3/fpm/pool.d/rynx-acme.conf'
    if (-not (Test-Path $poolConf)) { throw 'php pool was not rendered' }

    Write-Host '==> one-click installer'
    $install = PostJson '/api/v1/installer/install' @{
        username = 'acme'; domain = 'laravel.example.com'; app = 'laravel'
        php_version = '8.3'; title = 'Smoke Laravel'; tls = $false
    }
    $job = $install
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        if ($job.status -eq 'succeeded' -or $job.status -eq 'failed') { break }
        Start-Sleep -Milliseconds 250
        $job = RequestJson 'GET' "/api/v1/installer/jobs/$($job.id)"
    }
    if ($job.status -ne 'succeeded') { throw "installer failed: $($job.message)" }
    if (-not $job.db_password) { throw 'installer did not return the database password' }
    $laravelConf = Join-Path $root 'data/daemon/sandbox/nginx/sites-available/laravel.example.com.conf'
    if (-not (Test-Path $laravelConf)) { throw 'installer website was not created' }
    if (-not (Select-String -Path $laravelConf -Pattern 'root .*laravel\.example\.com/public_html/public;' -Quiet)) {
        throw 'Laravel document root was not updated to public/'
    }
    $laravelRoot = Join-Path $root 'data/daemon/sandbox/home/acme/laravel.example.com/public_html'
    if (-not (Test-Path (Join-Path $laravelRoot '.env'))) { throw 'installer .env was not written' }
    if (-not (Test-Path (Join-Path $laravelRoot 'public/index.php'))) { throw 'installer public root missing' }
    $installerDb = RequestJson 'GET' '/api/v1/databases'
    if (-not ($installerDb.databases | Where-Object { $_.domain -eq 'laravel.example.com' })) {
        throw 'installer did not create the database'
    }

    Write-Host '==> website delete cascade'
    $null = PostJson '/api/v1/mail/domains' @{
        domain = 'laravel.example.com'; username = 'acme'; enabled = $true; catch_all = $null
    }
    $null = PostJson '/api/v1/mail/accounts' @{
        domain = 'laravel.example.com'; local_part = 'info'; password = 'Mail-Pass-1234'
        quota_mb = 100; enabled = $true
    }
    $null = PostJson '/api/v1/ftp' @{
        domain = 'laravel.example.com'; username = 'larainstall'; readonly = $false
    }
    $null = RequestJson 'POST' '/api/v1/databases' @{ domain = 'laravel.example.com'; name = 'cleanup' }
    $null = RequestJson 'DELETE' '/api/v1/websites/laravel.example.com'
    if ((RequestJson 'GET' '/api/v1/websites').websites | Where-Object { $_.spec.domain -eq 'laravel.example.com' }) {
        throw 'website was not deleted'
    }
    if ((RequestJson 'GET' '/api/v1/databases').databases | Where-Object { $_.domain -eq 'laravel.example.com' }) {
        throw 'website databases were not deleted'
    }
    if ((RequestJson 'GET' '/api/v1/mail/domains').domains | Where-Object { $_.domain -eq 'laravel.example.com' }) {
        throw 'mail domain was not deleted'
    }
    if ((RequestJson 'GET' '/api/v1/mail/accounts').accounts | Where-Object { $_.domain -eq 'laravel.example.com' }) {
        throw 'mailboxes were not deleted'
    }
    if ((RequestJson 'GET' '/api/v1/ftp').accounts | Where-Object { $_.domain -eq 'laravel.example.com' }) {
        throw 'FTP accounts were not deleted'
    }
    if (Test-Path $laravelConf) { throw 'website vhost was not removed' }
    $webmailConf = Join-Path $root 'data/daemon/sandbox/nginx/sites-available/webmail.laravel.example.com.conf'
    if (Test-Path $webmailConf) { throw 'webmail vhost was not removed' }
    $dkimDir = Join-Path $root 'data/daemon/sandbox/opendkim/keys/laravel.example.com'
    if (Test-Path $dkimDir) { throw 'DKIM keys were not removed' }
    $zoneFile = Join-Path $root 'data/daemon/sandbox/bind/zones/laravel.example.com.db'
    if (Test-Path $zoneFile) { throw 'DNS zone was not removed' }

    Write-Host '==> file manager'
    $files = RequestJson 'GET' '/api/v1/files?domain=php.example.com&path='
    if (-not ($files.entries | Where-Object { $_.name -like 'index.*' })) {
        throw 'file manager did not list the site root'
    }
    $null = RequestJson 'POST' '/api/v1/files/mkdir' @{ domain = 'php.example.com'; path = ''; name = 'assets' }
    $hello = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('hello'))
    $null = RequestJson 'POST' '/api/v1/files/upload' @{
        domain = 'php.example.com'; path = 'assets'; name = 'hello.txt'; data = $hello
    }
    $readFile = RequestJson 'GET' '/api/v1/files/read?domain=php.example.com&path=assets%2Fhello.txt'
    if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($readFile.data)) -ne 'hello') {
        throw 'file read failed'
    }
    $bye = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('bye'))
    $null = RequestJson 'PUT' '/api/v1/files/write' @{
        domain = 'php.example.com'; path = 'assets/hello.txt'; data = $bye
    }
    $null = RequestJson 'POST' '/api/v1/files/rename' @{
        domain = 'php.example.com'; path = 'assets/hello.txt'; new_name = 'bye.txt'
    }
    $renamed = RequestJson 'GET' '/api/v1/files/read?domain=php.example.com&path=assets%2Fbye.txt'
    if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($renamed.data)) -ne 'bye') {
        throw 'file rename failed'
    }
    $null = RequestJson 'DELETE' '/api/v1/files?domain=php.example.com&path=assets%2Fbye.txt&recursive=false'
    $null = RequestJson 'DELETE' '/api/v1/files?domain=php.example.com&path=assets&recursive=true'
    ExpectStatus 400 { RequestJson 'GET' '/api/v1/files?domain=php.example.com&path=..%2F..%2Fetc%2Fpasswd' }
    ExpectStatus 404 { RequestJson 'GET' '/api/v1/files?domain=missing.example.com&path=' }

    Write-Host '==> account suspension/resume'
    $suspended = PostJson '/api/v1/accounts' @{
        username = 'acme'; email = 'acme@example.com'; disk_limit_mb = 2048
        php_version = '8.3'; enabled = $false
    }
    if ($suspended.account.account.spec.enabled) { throw 'account was not suspended' }
    if (Test-Path $siteConf) { throw 'suspended account still has an enabled vhost' }
    $resumed = PostJson '/api/v1/accounts' @{
        username = 'acme'; email = 'acme@example.com'; disk_limit_mb = 2048
        php_version = '8.3'; enabled = $true
    }
    if (-not $resumed.account.account.spec.enabled) { throw 'account was not resumed' }
    if (-not (Test-Path $siteConf)) { throw 'resumed account vhost was not restored' }

    Write-Host '==> dns'
    $dns = RequestJson 'GET' '/api/v1/dns'
    if ($dns.kind -ne 'dns_zones' -or $dns.zones.Count -lt 2) { throw 'expected DNS zones for both websites' }
    $zone = $dns.zones | Where-Object { $_.domain -eq 'example.com' } | Select-Object -First 1
    if (-not ($zone.records | Where-Object { $_.spec.name -eq '_dmarc' })) { throw 'DMARC record missing' }
    if (-not ($zone.records | Where-Object { $_.spec.name -like '*._domainkey' })) { throw 'DKIM record missing' }
    $zoneFile = Join-Path $root 'data/daemon/sandbox/bind/zones/example.com.db'
    if (-not (Select-String -Path $zoneFile -Pattern 'v=DMARC1' -Quiet)) { throw 'DMARC not rendered in zone file' }

    $record = RequestJson 'POST' '/api/v1/dns/example.com/records' @{
        domain = 'example.com'; name = 'status'; rtype = 'A'; value = '203.0.113.55'; ttl = 300; priority = $null
    }
    $newRecord = $record.zone.records | Where-Object { $_.spec.name -eq 'status' } | Select-Object -First 1
    if (-not $newRecord) { throw 'manual DNS record was not added' }
    $null = RequestJson 'DELETE' "/api/v1/dns/example.com/records/$($newRecord.id)"
    $null = RequestJson 'POST' '/api/v1/dns/example.com/mail'

    Write-Host '==> databases and ftp'
    $database = RequestJson 'POST' '/api/v1/databases' @{ domain = 'example.com'; name = 'smoke' }
    if ($database.kind -ne 'database') { throw 'database creation failed' }
    if ($database.database.username -notlike 'acme_*') { throw 'unexpected database name' }
    if (-not ((RequestJson 'GET' '/api/v1/databases').databases | Where-Object { $_.id -eq $database.database.id })) {
        throw 'created database is missing from the list'
    }

    $ftp = RequestJson 'POST' '/api/v1/ftp' @{ domain = 'example.com'; username = 'deploy'; readonly = $false }
    if ($ftp.kind -ne 'ftp') { throw 'ftp account creation failed' }
    if ($ftp.account.password.Length -lt 12) { throw 'ftp password is too short' }
    if ((RequestJson 'GET' '/api/v1/ftp').accounts.Count -ne 1) { throw 'expected one ftp account' }

    Write-Host '==> backups'
    $backup = RequestJson 'POST' '/api/v1/backups' @{ username = 'acme' }
    if ($backup.kind -ne 'backup') { throw 'backup creation failed' }
    if (-not (Test-Path $backup.backup.path)) { throw 'backup file does not exist' }
    if ((RequestJson 'POST' "/api/v1/backups/$($backup.backup.id)/restore").kind -ne 'ack') { throw 'backup restore failed' }

    Write-Host '==> certificates'
    $secureSite = PostJson '/api/v1/websites' @{
        domain = 'secure.example.com'; username = 'acme'; aliases = @('www.secure.example.com')
        runtime = @{ engine = 'static' }; app = $null
        docroot = 'public_html'; tls = 'lets_encrypt'; enabled = $true
    }
    if ($secureSite.kind -ne 'website') { throw 'secure website creation failed' }
    $cert = RequestJson 'POST' '/api/v1/certs' @{ domain = 'secure.example.com'; email = 'admin@example.com'; staging = $false }
    if ($cert.kind -ne 'cert') { throw 'certificate issue failed' }
    $secureConf = Join-Path $root 'data/daemon/sandbox/nginx/sites-available/secure.example.com.conf'
    if (-not (Select-String -Path $secureConf -Pattern 'listen 443 ssl' -Quiet)) { throw 'vhost was not upgraded to TLS' }
    if (-not (Select-String -Path $secureConf -Pattern 'return 301 https://' -Quiet)) { throw 'TLS vhost does not redirect HTTP by default' }
    $secureFalse = PostJson '/api/v1/websites' @{
        domain = 'secure.example.com'; username = 'acme'; aliases = @('www.secure.example.com')
        runtime = @{ engine = 'static' }; app = $null
        docroot = 'public_html'; tls = 'lets_encrypt'; force_https = $false; enabled = $true
    }
    if ($secureFalse.website.spec.force_https -ne $false) { throw 'force_https=false was not persisted' }
    $secureTrue = PostJson '/api/v1/websites' @{
        domain = 'secure.example.com'; username = 'acme'; aliases = @('www.secure.example.com')
        runtime = @{ engine = 'static' }; app = $null
        docroot = 'public_html'; tls = 'lets_encrypt'; force_https = $true; enabled = $true
    }
    if ($secureTrue.website.spec.force_https -ne $true) { throw 'force_https=true was not persisted' }
    if ((RequestJson 'POST' '/api/v1/certs/renew').kind -ne 'ack') { throw 'certificate renew failed' }

    Write-Host '==> monitor, programs, console'
    $services = RequestJson 'GET' '/api/v1/monitor/services'
    if ($services.kind -ne 'service_stats' -or $services.services.Count -lt 2) { throw 'service stats missing' }
    if ((RequestJson 'GET' '/api/v1/monitor/history?minutes=1440').kind -ne 'metrics_history') { throw 'metrics history missing' }
    $programs = RequestJson 'GET' '/api/v1/system/programs'
    if ($programs.kind -ne 'programs' -or $programs.programs.Count -lt 5) { throw 'programs list missing' }
    $nginxProgram = @($programs.programs) | Where-Object { $_.name -eq 'nginx' }
    if ($null -eq $nginxProgram -or -not $nginxProgram.unit) { throw 'program service unit missing' }
    if ($nginxProgram.service_status -ne 'active') { throw 'program service status missing' }
    $programAction = RequestJson 'POST' '/api/v1/system/programs/nginx/restart'
    if ($programAction.kind -ne 'console_output') { throw 'program restart action failed' }
    ExpectStatus 400 {
        RequestJson 'POST' '/api/v1/system/programs/nginx/explode'
    }
    if ((RequestJson 'GET' '/api/v1/system/updates').kind -ne 'updates') { throw 'updates list missing' }
    $filters = RequestJson 'GET' '/api/v1/mail/filters'
    if (@($filters.programs).Count -lt 2) { throw 'mail filter programs missing' }
    if (@($filters.events).Count -lt 1) { throw 'mail filter activity missing' }
    $agentRun = RequestJson 'POST' '/api/v1/agent/run'
    if ($agentRun.run.status -ne 'ok') { throw 'agent run failed' }
    $agentFindings = RequestJson 'GET' '/api/v1/agent/findings?status=all&limit=50'
    if (@($agentFindings.findings).Count -lt 1) { throw 'agent findings missing' }
    $agentId = @($agentFindings.findings)[0].id
    $null = RequestJson 'POST' "/api/v1/agent/findings/$agentId/status" @{ status = 'acknowledged' }
    $agentProvider = RequestJson 'POST' '/api/v1/agent/provider/test'
    if ($null -eq $agentProvider.ok) { throw 'agent provider test missing' }
    $console = RequestJson 'POST' '/api/v1/console' @{ action = @{ action = 'disk_usage' } }
    if ($console.kind -ne 'console_output' -or -not $console.output) { throw 'console action failed' }

    Write-Host '==> firewall'
    if ((RequestJson 'GET' '/api/v1/firewall').kind -ne 'firewall') { throw 'firewall status missing' }
    $null = RequestJson 'POST' '/api/v1/firewall/rules' @{ action = 'allow'; proto = 'tcp'; port = 8443; source = '203.0.113.0/24'; comment = 'test' }
    $fw = RequestJson 'POST' '/api/v1/firewall/block' @{ ip = '198.51.100.7'; seconds = 3600; reason = 'test' }
    if (-not ($fw.state.blocked | Where-Object { $_.ip -eq '198.51.100.7' })) { throw 'blocked IP not stored' }
    $fw = RequestJson 'POST' '/api/v1/firewall/whitelist' @{ ip = '198.51.100.8' }
    if (-not ($fw.state.whitelist -contains '198.51.100.8')) { throw 'whitelist not stored' }
    $null = RequestJson 'DELETE' '/api/v1/firewall/block/198.51.100.7'
    $null = RequestJson 'DELETE' '/api/v1/firewall/whitelist/198.51.100.8'
    $rulesetFile = Join-Path $root 'data/daemon/sim-firewall/ruleset.nft'
    if (-not (Test-Path $rulesetFile)) { throw 'firewall ruleset was not generated' }
    if (-not (Select-String -Path $rulesetFile -Pattern 'policy drop' -Quiet)) {
        throw 'firewall is not using a default-drop policy'
    }

    Write-Host '==> security and impersonation'
    $stats = RequestJson 'GET' '/api/v1/security/stats?hours=24'
    if ($null -eq $stats.failures) { throw 'security stats missing' }
    $events = RequestJson 'GET' '/api/v1/security/auth-events?limit=50'
    if ($events.events.Count -lt 1) { throw 'auth events missing' }

    Write-Host '==> panel email endpoints'
    $mailStatus = RequestJson 'GET' '/api/v1/system/email'
    if ($mailStatus.enabled) { throw 'SMTP should be disabled in the smoke configuration' }
    $forgot = Invoke-RestMethod -Uri "$base/api/v1/auth/forgot-password" -Method Post `
        -ContentType 'application/json' `
        -Body (@{ email = 'admin@example.com' } | ConvertTo-Json)
    if (-not $forgot.ok) { throw 'forgot-password did not return a generic ok' }
    ExpectStatus 400 {
        Invoke-RestMethod -Uri "$base/api/v1/auth/reset-password" -Method Post `
            -ContentType 'application/json' `
            -Body (@{ token = ('0' * 64); password = 'Reset-Strong-Pass2' } | ConvertTo-Json)
    }

    $viewer = PostJson '/api/v1/users' @{
        username = 'viewer1'; email = 'viewer1@example.com'; password = 'Viewer-Strong-Pass3'; role = 'viewer'
    }
    if ($viewer.role -ne 'viewer') { throw 'viewer creation failed' }
    $impersonated = RequestJson 'POST' '/api/v1/users/viewer1/impersonate'
    if ($impersonated.impersonated_by -ne 'admin' -or $impersonated.user.username -ne 'viewer1') {
        throw 'impersonation response is invalid'
    }
    $headers['x-csrf-token'] = $impersonated.csrf_token
    $me = RequestJson 'GET' '/api/v1/auth/me'
    if ($me.user.username -ne 'viewer1' -or $me.impersonated_by -ne 'admin') { throw 'impersonated session is invalid' }
    $restored = RequestJson 'POST' '/api/v1/auth/stop-impersonation'
    if ($restored.user.username -ne 'admin' -or $restored.impersonated_by) { throw 'stop impersonation failed' }
    $headers['x-csrf-token'] = $restored.csrf_token

    Write-Host '==> packages'
    $packages = @(RequestJson 'GET' '/api/v1/packages')
    if ($packages.Count -ne 1 -or -not $packages[0].is_default) {
        throw 'the default package was not seeded'
    }
    $defaultPackage = $packages[0]
    $newPackage = PostJson '/api/v1/packages' @{
        name = 'Smoke Plan'; account_mb = 500; bandwidth_mb = 0; backups = 2
        incremental_backup = $true; web_domains = 10; web_aliases = 20
        web_backend = 'php'; nginx_template = 'hosting'; dns_template = 'child-ns'
        dns_zones = 0; dns_records = 0; nameservers = @('ns1.example.tld', 'ns2.example.tld')
        mail_domains = 5; mail_accounts = 10; mail_rate_limit = 0
        databases = 3; system_databases = 0
    }
    if ($newPackage.name -ne 'Smoke Plan' -or $newPackage.is_default -or $newPackage.account_mb -ne 500) {
        throw 'package creation failed'
    }
    $updateBody = PackageBody $newPackage
    $updateBody.account_mb = 200
    $updatedPackage = RequestJson 'PATCH' "/api/v1/packages/$($newPackage.id)" $updateBody
    if ($updatedPackage.account_mb -ne 200 -or -not $updatedPackage.incremental_backup) {
        throw 'package update failed'
    }
    $defaultBody = PackageBody $defaultPackage
    $defaultBody.account_mb = 1
    $editedDefault = RequestJson 'PATCH' "/api/v1/packages/$($defaultPackage.id)" $defaultBody
    if (-not $editedDefault.is_default) { throw 'the default package lost its flag' }
    ExpectStatus 409 { RequestJson 'DELETE' "/api/v1/packages/$($defaultPackage.id)" }

    $pkgAccount = PostJson '/api/v1/accounts' @{
        username = 'pkgacct'; email = 'pkgacct@example.com'; disk_limit_mb = 1
        php_version = $null; enabled = $true
        package_id = $newPackage.id; web_backend = 'node'
    }
    if ($pkgAccount.account.account.spec.disk_limit_mb -ne 200 -or $pkgAccount.package.web_backend -ne 'node') {
        throw 'the account did not inherit the package limits'
    }
    ExpectStatus 409 { RequestJson 'DELETE' "/api/v1/packages/$($newPackage.id)" }
    $null = RequestJson 'DELETE' '/api/v1/accounts/pkgacct?purge=true'
    $null = RequestJson 'DELETE' "/api/v1/packages/$($newPackage.id)"

    Write-Host '==> combined website/app package limit'
    $comboBody = PackageBody $newPackage
    $comboBody.name = 'Combined Plan'
    $comboBody.web_domains = 1
    $comboPackage = PostJson '/api/v1/packages' $comboBody
    $comboAccount = PostJson '/api/v1/accounts' @{
        username = 'combo'; email = 'combo@example.com'; disk_limit_mb = 100
        php_version = $null; enabled = $true
        package_id = $comboPackage.id; web_backend = 'php'
    }
    if ($comboAccount.account.kind -ne 'account') { throw 'combined limit account was not created' }
    $null = PostJson '/api/v1/apps' @{
        username = 'combo'; name = 'api'; runtime = @{ engine = 'node'; version = '22' }
        port = 4111; entrypoint = 'server.js'; command = 'node'
        args = @('server.js'); env = @{ NODE_ENV = 'production' }; enabled = $true
    }
    ExpectStatus 409 {
        PostJson '/api/v1/websites' @{
            domain = 'combo.example.com'; username = 'combo'; aliases = @()
            runtime = @{ engine = 'php'; version = '8.3' }; app = $null
            docroot = 'public_html'; tls = 'disabled'; enabled = $true
        }
    }
    $null = RequestJson 'DELETE' '/api/v1/apps/combo/api'
    $null = PostJson '/api/v1/websites' @{
        domain = 'combo.example.com'; username = 'combo'; aliases = @()
        runtime = @{ engine = 'php'; version = '8.3' }; app = $null
        docroot = 'public_html'; tls = 'disabled'; enabled = $true
    }
    ExpectStatus 409 {
        PostJson '/api/v1/apps' @{
            username = 'combo'; name = 'api2'; runtime = @{ engine = 'node'; version = '22' }
            port = 4112; entrypoint = 'server.js'; command = 'node'
            args = @('server.js'); env = @{ NODE_ENV = 'production' }; enabled = $true
        }
    }
    $null = RequestJson 'DELETE' '/api/v1/accounts/combo?purge=true'
    $null = RequestJson 'DELETE' "/api/v1/packages/$($comboPackage.id)"

    Write-Host '==> security checks'
    ExpectStatus 400 {
        PostJson '/api/v1/accounts' @{
            username = 'root'; email = 'root@example.com'; disk_limit_mb = 1024
            php_version = $null; enabled = $true
        }
    }
    ExpectStatus 409 {
        RequestJson 'POST' '/api/v1/databases' @{ domain = 'example.com'; name = 'smoke' }
    }
    ExpectStatus 403 {
        $login2 = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method Post `
            -ContentType 'application/json' `
            -Body (@{ username = 'admin'; password = 'Sup3r-Secret-Pass' } | ConvertTo-Json) `
            -SessionVariable fresh
        $null = $login2.csrf_token
        Invoke-RestMethod -Uri "$base/api/v1/accounts" -Method Post -WebSession $fresh `
            -ContentType 'application/json' `
            -Body (@{ username = 'nocsrf'; email = 'n@example.com'; disk_limit_mb = 1024; php_version = $null; enabled = $true } | ConvertTo-Json)
    }
    ExpectStatus 401 {
        Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method Post -ContentType 'application/json' `
            -Body (@{ username = 'admin'; password = 'wrong-password' } | ConvertTo-Json)
    }
    $anon = 0
    try {
        Invoke-RestMethod -Uri "$base/api/v1/accounts" | Out-Null
        $anon = 200
    } catch {
        $anon = [int]$_.Exception.Response.StatusCode
    }
    if ($anon -ne 401) { throw "unauthenticated access returned $anon" }

    Write-Host '==> audit and reconcile'
    $audit = RequestJson 'GET' '/api/v1/audit?limit=50'
    if ($audit.entries.Count -lt 8) { throw 'audit log is missing events' }
    if ($audit.entries[-1].hash.Length -ne 64) { throw 'audit hashes are malformed' }
    if ((RequestJson 'POST' '/api/v1/reconcile').kind -ne 'ack') { throw 'reconcile did not return an ack' }

    Write-Host '==> cleanup'
    $null = RequestJson 'DELETE' "/api/v1/ftp/$($ftp.account.id)"
    $null = RequestJson 'DELETE' "/api/v1/databases/$($database.database.id)"
    $null = RequestJson 'DELETE' "/api/v1/backups/$($backup.backup.id)"

    Write-Host ''
    Write-Host 'SMOKE OK: auth, RBAC, CSRF, packages, accounts, runtimes, files, DNS, DB, FTP, backups, TLS, monitor, mail filters, agent, console, firewall, impersonation, panel email, audit, reconcile.'
} finally {
    if ($api -and -not $api.HasExited) { Stop-Process -Id $api.Id -Force }
    if ($daemon -and -not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force }
}
