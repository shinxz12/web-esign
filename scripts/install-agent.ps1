<#
.SYNOPSIS
    Cài đặt Web Signer Agent trên Windows.

.DESCRIPTION
    1. Sao chép WebSignerAgent.exe vào %LOCALAPPDATA%\Programs\WebSignerAgent
    2. Tạo shortcut trong Start Menu và Desktop
    3. Đăng ký tự khởi động cùng Windows (Run key)
    4. Khởi chạy agent
#>
[CmdletBinding()]
param(
    [switch]$NoStart,
    [switch]$NoAutostart
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$sourceExe = Join-Path $root "dist\WebSignerAgent.exe"

if (-not (Test-Path $sourceExe)) {
    Write-Host "Chưa có dist\WebSignerAgent.exe — đang build..."
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build-agent.ps1")
    if (-not (Test-Path $sourceExe)) {
        throw "Build thất bại, không tìm thấy $sourceExe"
    }
}

$installDir = Join-Path $env:LOCALAPPDATA "Programs\WebSignerAgent"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

$targetExe = Join-Path $installDir "WebSignerAgent.exe"

# Dừng tiến trình cũ nếu đang chạy để ghi đè file
$existing = Get-Process -Name "WebSignerAgent" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Đang dừng WebSignerAgent đang chạy..."
    Stop-Process -Name "WebSignerAgent" -Force
    Start-Sleep -Seconds 1
}

Write-Host "Đang sao chép file tới $targetExe..."
Copy-Item -Path $sourceExe -Destination $targetExe -Force

# Tạo shortcut bằng WScript.Shell
$wsh = New-Object -ComObject WScript.Shell

# 1. Start Menu Shortcut
$startMenuDir = [Environment]::GetFolderPath("Programs")
if ($startMenuDir -and (Test-Path $startMenuDir)) {
    $shortcutPath = Join-Path $startMenuDir "Web Signer Agent.lnk"
    $shortcut = $wsh.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $targetExe
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Description = "Web Signer Agent"
    $shortcut.Save()
    Write-Host "Đã tạo shortcut Start Menu: $shortcutPath"
}

# 2. Desktop Shortcut
$desktopDir = [Environment]::GetFolderPath("Desktop")
if ($desktopDir -and (Test-Path $desktopDir)) {
    $desktopShortcutPath = Join-Path $desktopDir "Web Signer Agent.lnk"
    $shortcut = $wsh.CreateShortcut($desktopShortcutPath)
    $shortcut.TargetPath = $targetExe
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Description = "Web Signer Agent"
    $shortcut.Save()
    Write-Host "Đã tạo shortcut Desktop: $desktopShortcutPath"
}

# 3. Đăng ký Run key (Autostart)
if (-not $NoAutostart) {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $cmd = "`"$targetExe`" --autoconnect --silent"
    Set-ItemProperty -Path $runKey -Name "WebSignerAgent" -Value $cmd
    Write-Host "Đã đăng ký tự khởi động cùng Windows: $cmd"
}

Write-Host ""
Write-Host "==> Cài đặt thành công Web Signer Agent!"
Write-Host "Vị trí: $targetExe"

# 4. Khởi chạy agent
if (-not $NoStart) {
    Write-Host "Đang khởi chạy Web Signer Agent..."
    Start-Process -FilePath $targetExe -ArgumentList "--autoconnect --silent"
}
