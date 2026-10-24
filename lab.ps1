# lab.ps1 — local lab (Windows): vulnerable PHP 8.4.26 on :8088, patched 8.5.12 on :8089
# Mirrors lab_setup.sh. Needs Docker Desktop running (~1.2 GB pull).
$ErrorActionPreference = "Stop"

# Friendly pre-check: Docker Desktop must be running before touching anything.
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Docker engine is not running." -ForegroundColor Yellow
    Write-Host "    Start Docker Desktop from the Start menu, wait for 'Engine running',"
    Write-Host "    then re-run .\lab.ps1"
    exit 1
}

$HERE = Split-Path -Parent $MyInvocation.MyCommand.Path
$D = Join-Path $HERE "lab"
New-Item -ItemType Directory -Force -Path (Join-Path $D "out"), (Join-Path $D "www") | Out-Null

$phpIni = @"
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M
session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
log_errors = On
"@
Set-Content -Path (Join-Path $D "php.ini") -Value $phpIni -Encoding ascii

$apacheConf = @"
KeepAlive Off
<IfModule mpm_prefork_module>
    StartServers           1
    MinSpareServers        1
    MaxSpareServers        1
    MaxRequestWorkers      1
    ServerLimit            1
    MaxConnectionsPerChild 0
</IfModule>
"@
Set-Content -Path (Join-Path $D "apache.conf") -Value $apacheConf -Encoding ascii

Set-Content -Path (Join-Path $D "www\index.php") -Value '<?php echo "OK\n"; ?>' -Encoding ascii

function Start-Lab([string]$name, [string]$image, [int]$port) {
    docker rm -f $name 2>$null | Out-Null
    docker run -d --name $name --platform linux/amd64 -p "127.0.0.1:${port}:80" `
        -v "$(Join-Path $D 'php.ini'):/usr/local/etc/php/conf.d/zz-php2shell.ini:ro" `
        -v "$(Join-Path $D 'apache.conf'):/etc/apache2/conf-enabled/zz-php2shell.conf:ro" `
        -v "$(Join-Path $D 'www'):/var/www/html:ro" `
        -v "$(Join-Path $D 'out'):/out" `
        $image | Out-Null
}

Start-Lab "php2shell-target"  "php:8.4.26-apache" 8088
Start-Lab "php2shell-patched" "php:8.5.12-apache" 8089
Start-Sleep -Seconds 4

docker ps --format "{{.Names}}  {{.Image}}  {{.Ports}}"
foreach ($p in 8088, 8089) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$p/index.php" -TimeoutSec 10
        Write-Host "  :$p -> $($r.StatusCode)"
    } catch {
        Write-Host "  :$p -> falhou"
    }
}

Write-Host ""
Write-Host "[+] lab no ar:"
Write-Host "    vulneravel: http://127.0.0.1:8088/index.php  (PHP 8.4.26)"
Write-Host "    corrigido : http://127.0.0.1:8089/index.php  (PHP 8.5.12)"
Write-Host ""
Write-Host "    recon:      python php2shell.py -u http://127.0.0.1:8088/index.php --recon-only"
Write-Host "    preflight:  python php2shell.py -u http://127.0.0.1:8088/index.php --preflight-only"
Write-Host "    exploit:    python php2shell.py -u http://127.0.0.1:8088/index.php -c 'id>/out/p'"
Write-Host "    prova:      Get-Content lab\out\p"
Write-Host "    desligar:   docker rm -f php2shell-target php2shell-patched"
