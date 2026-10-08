# TRAE SOLO CN 每日签到：Windows 计划任务安装脚本
# 用法：以当前用户身份运行  powershell -ExecutionPolicy Bypass -File .\install-windows.ps1
#   -TaskName  任务名（默认 TraeSoloSignin）
#   -Time      每日运行时间（默认 09:05）
#   -Uninstall 卸载计划任务
#
# 任务特性：
#   - 每日定点跑一次 silent 模式（结果写 signin.log）
#   - 错过执行点（关机/睡眠）时，下次开机尽快补跑（StartWhenAvailable）
#   - 网络类失败脚本内部自带退避重试，无需任务级重试

param(
    [string]$TaskName = "TraeSoloSignin",
    [string]$Time = "09:05",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "已卸载计划任务 $TaskName"
    exit 0
}

# 定位 python：优先 pythonw（无窗口），回退 python
$python = Get-Command pythonw.exe -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python.exe -ErrorAction SilentlyContinue }
if (-not $python) {
    # 常见安装路径兜底
    foreach ($p in @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python39\pythonw.exe"
    )) {
        if (Test-Path $p) { $python = @{ Source = $p }; break }
    }
}
if (-not $python) {
    Write-Error "未找到 python，请先安装 Python 3 并加入 PATH"
    exit 1
}

$script = Join-Path $PSScriptRoot "trae_signin.py"
if (-not (Test-Path $script)) {
    Write-Error "未找到 $script"
    exit 1
}

# 先手动跑一次 doctor 验证凭据可用
# 先手动跑一次 doctor 验证凭据可用。
# 注意：pythonw.exe 是 GUI 子系统程序，PowerShell 不会回传其退出码，
# 因此自检改用同目录的 python.exe（找不到则跳过检测）。
$pyCli = $python.Source -replace "pythonw\.exe$", "python.exe"
if (-not (Test-Path $pyCli)) { $pyCli = (Get-Command python.exe -ErrorAction SilentlyContinue).Source }
if ($pyCli) { & $pyCli $script doctor }
if ($pyCli -and $LASTEXITCODE -ne 0) {
    Write-Warning "doctor 自检未完全通过，任务仍会安装；请先登录 TRAE SOLO CN 桌面端。"
}

$action = New-ScheduledTaskAction -Execute $python.Source -Argument "`"$script`" silent"
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Description "TRAE SOLO CN 每日签到（silent 模式，结果写入 signin.log）" -Force | Out-Null

Write-Host ""
Write-Host "已安装计划任务 $TaskName ：每日 $Time 运行"
Write-Host "日志：$PSScriptRoot\signin.log"
Write-Host "立即试跑一次："
Write-Host "  powershell Start-ScheduledTask -TaskName $TaskName"
