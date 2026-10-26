# Đóng gói agent thành dist\WebSignerAgent.exe
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-agent.ps1
#
# Chạy trên chính Windows: PyInstaller không cross-build, muốn có .exe thì
# phải build trên Windows (máy thật, VM hoặc runner windows-latest).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "Chưa có .venv — tạo mới…"
    py -3.12 -m venv .venv
    $python = Join-Path $root ".venv\Scripts\python.exe"
    & $python -m pip install --upgrade pip
    & $python -m pip install -r requirements-dev.txt
}

# python-pkcs11 chỉ cần khi ký bằng USB token thật; thiếu nó thì bản đóng gói
# chạy được nhưng không mở được token, nên kiểm tra sớm.
& $python -c "import pkcs11" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Thiếu python-pkcs11: bản .exe sẽ không mở được USB token."
}

& $python -m PyInstaller --noconfirm scripts\websigner-agent.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller thất bại" }

$exe = Join-Path $root "dist\WebSignerAgent.exe"
Write-Host ""
Write-Host "Xong: $exe"
Write-Host "Gửi đúng một tệp này cho người ký. Mở lên, chọn nguồn khoá, bấm"
Write-Host "Kết nối; tích 'Chạy khi khởi động máy' nếu muốn bật cùng Windows."

# Ký chính tệp .exe để SmartScreen không chặn (cần chứng thư code signing):
#   signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
#     /f code-signing.pfx /p <mật khẩu> dist\WebSignerAgent.exe
