<#
.SYNOPSIS
    Cài phụ thuộc rồi chạy Web Signer Agent trên Windows.

.DESCRIPTION
    Agent đọc USB token qua Windows Certificate Store (CNG/CSP). Phần mềm ký
    của CA (I-CA, Viettel-CA, VNPT-CA, FPT-CA, BKAV...) đã đăng ký token vào
    store "MY", nên không cần biết driver của hãng nào.

    Khoá riêng không rời token. Agent chỉ nhận vài trăm byte signed attributes
    từ server, đưa token ký, rồi trả chữ ký về.

.EXAMPLE
    .\scripts\windows-agent.ps1
    .\scripts\windows-agent.ps1 -Server wss://web-signer.btngoc.io.vn/ws/agent
    .\scripts\windows-agent.ps1 -ListOnly
#>
[CmdletBinding()]
param(
    [string]$Server = "wss://web-signer.btngoc.io.vn/ws/agent",
    [string]$Code,
    [string]$Store = "MY",
    # Chỉ nhận khoá nằm trên token. Bật khi store có lẫn chứng thư khoá mềm.
    [switch]$HardwareOnly,
    # Chỉ liệt kê chứng thư rồi thoát — dùng để chẩn đoán.
    [switch]$ListOnly,
    # Dùng DLL PKCS#11 của CA thay cho CNG.
    [switch]$UsePkcs11
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv-agent"
$python = Join-Path $venv "Scripts\python.exe"

function Resolve-Python {
    foreach ($candidate in @("py", "python", "python3")) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    throw "Chưa có Python. Cài Python 3.10+ từ https://www.python.org/downloads/ rồi chạy lại."
}

if (-not (Test-Path $python)) {
    Write-Host "==> Tạo môi trường Python cho agent"
    & (Resolve-Python) -m venv $venv
    # Agent chỉ cần 3 gói; không kéo theo pyHanko của backend.
    & $python -m pip install --quiet --upgrade pip
    & $python -m pip install --quiet websockets cryptography python-pkcs11
}

$agent = Join-Path $root "agent\agent.py"
$argv = @($agent, "--server", $Server, "--cng-store", $Store)

if ($UsePkcs11) {
    # 'auto' dò DLL mà phần mềm ký của CA đã cài vào System32.
    $argv = @($agent, "--server", $Server, "--pkcs11", "auto")
} else {
    $argv += "--cng"
}
if ($HardwareOnly) { $argv += "--hardware-only" }
if ($ListOnly)     { $argv += "--list" }
if ($Code)         { $argv += @("--code", $Code) }

Write-Host "==> Chạy agent"
& $python @argv
exit $LASTEXITCODE
