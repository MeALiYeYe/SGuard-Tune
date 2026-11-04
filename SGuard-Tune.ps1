<#
.SYNOPSIS
    启动英雄联盟客户端（腾讯官方启动器 startup_runner.exe），并【默认】把
    SGuard64.exe / SGuardSvc64.exe 的优先级设为「低」、CPU 相关性设为「仅 CPU 3」
    （可在任务管理器 - 详细信息 中看到效果）。

.DESCRIPTION
    ⚠️ 重要：腾讯 ACE 反作弊会在以下情况弹“安全组件运行异常”(13, 131083, 140) 并拒绝进游戏：
      1) 用 explorer/PowerShell 直接拉起 LeagueClient.exe（绕过官方启动链，ACE 不信任该父进程）；
      2) 以“管理员身份”运行游戏（被 ACE 判定为环境异常）；
      3) 改写其受保护进程的优先级/相关性（即本脚本的优化动作，少数情况下会被拦）。
    因此脚本的行为是：
      1) 走腾讯官方启动器（Launcher\startup_runner.exe）启动链——它会拉起 Riot 客户端
         与游戏本体，ACE 信任该启动链；
      2) 启动游戏时【始终以普通用户身份】拉起：即使脚本自身是管理员（为了改 ACE 进程必须提权），
         也会自动降权后再启动客户端，避免踩到第 2 条；
      3) 脚本自身需要管理员权限（改写 SYSTEM 级 ACE 进程需要），双击后会弹一次 UAC。
    【默认】即执行 SGuard 优化；若只想启动客户端、不动 ACE，请加 -NoTune。

.PARAMETER Cpu
    目标 CPU 编号（0 基）。默认 3 → 即任务管理器里的 CPU 3。

.PARAMETER Priority
    优先级：Idle(低，默认) / BelowNormal / Normal。

.PARAMETER NoTune
    跳过 SGuard 优化，只启动客户端（不改优先级/相关性，不需要管理员权限）。

.PARAMETER NoLaunch
    不启动客户端，只对已在运行的 SGuard 进程生效（需与默认优化行为配合使用）。

.PARAMETER Once
    只应用一次并退出（不常驻守护）。

.PARAMETER Status
    只查看当前 SGuard 进程的优先级与相关性，不做任何修改。

.EXAMPLE
    .\SGuard-Tune.ps1                         # 默认：启动客户端 + 优化 SGuard（低优先级、仅 CPU 3）
    .\SGuard-Tune.ps1 -Cpu 5                  # 换一个核（仅 CPU 5），其余不变
    .\SGuard-Tune.ps1 -NoTune                 # 只启动客户端，不碰 ACE（不提权）
    .\SGuard-Tune.ps1 -NoLaunch               # 不启动，仅对已在运行的 SGuard 做优化
    .\SGuard-Tune.ps1 -Status                 # 仅查看当前 SGuard 状态，不改任何东西
#>
[CmdletBinding()]
param(
    [int]$Cpu = 3,
    [ValidateSet('Idle', 'BelowNormal', 'Normal')]
    [string]$Priority = 'Idle',
    [string]$Shortcut,
    [string[]]$ProcessNames = @('SGuard64', 'SGuard64Svc64', 'SGuardSvc64'),
    [int]$IntervalMs = 2000,
    [int]$WaitSeconds = 300,
    [switch]$NoLaunch,
    [switch]$Once,
    [switch]$NoTune,
    [switch]$Status
)

$ErrorActionPreference = 'Stop'
$script:LogFile = Join-Path $env:LOCALAPPDATA 'SGuardTune\tune.log'

# ---------- 日志 ----------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = (Get-Date).ToString('HH:mm:ss')
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("[{0}] {1}" -f $ts, $Message) -ForegroundColor $color
    try {
        $dir = Split-Path -Parent $script:LogFile
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -LiteralPath $script:LogFile -Value ("{0} [{1}] {2}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message) -Encoding UTF8
    } catch { }
}

# ---------- 提权 ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 是否需要管理员/调试特权：默认就要优化 SGuard（改写 SYSTEM 级 ACE 进程），因此默认提权。
# 只有 -NoTune（仅启动客户端）时才是普通权限；-Status 也需要管理员才能读取 ACE 进程。
$NeedsPrivilege = (-not $NoTune) -or $Status

if ($NeedsPrivilege) {
    if (-not (Test-Admin)) {
        Write-Host '需要管理员权限（改写 SGuard 进程的优先级/相关性需要），正在请求提权...' -ForegroundColor Yellow
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        foreach ($k in $PSBoundParameters.Keys) {
            $v = $PSBoundParameters[$k]
            if ($v -is [switch]) { if ($v.IsPresent) { $argList += "-$k" } }
            elseif ($v -is [array]) { $argList += "-$k"; foreach ($i in $v) { $argList += "`"$i`"" } }
            else { $argList += "-$k"; $argList += "`"$v`"" }
        }
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs | Out-Null
        exit
    }
}

# ---------- 原生 API ----------
if (-not ('SGuardNative' -as [type])) {
    Add-Type -Language CSharp @'
using System;
using System.Runtime.InteropServices;

public static class SGuardNative
{
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_SET_INFORMATION   = 0x0200;

    public const uint NORMAL_PRIORITY_CLASS       = 0x00000020;
    public const uint IDLE_PRIORITY_CLASS         = 0x00000040;
    public const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetPriorityClass(IntPtr h, uint cls);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetPriorityClass(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetProcessAffinityMask")]
    private static extern bool SetProcessAffinityMaskNative(IntPtr h, UIntPtr mask);

    public static bool SetAffinity(IntPtr h, ulong mask)
    {
        if (mask == 0UL) return false;
        return SetProcessAffinityMaskNative(h, new UIntPtr(mask));
    }

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetProcessAffinityMask")]
    private static extern bool GetProcessAffinityMaskNative(IntPtr h, out UIntPtr procMask, out UIntPtr sysMask);

    public static ulong GetAffinity(IntPtr h)
    {
        UIntPtr p, s;
        if (!GetProcessAffinityMaskNative(h, out p, out s)) return 0UL;
        return p.ToUInt64();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previous, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    public static bool EnablePrivilege(string name)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out token)) return false;
        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, name, out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privilege.Luid = luid;
            tp.Privilege.Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
            return AdjustTokenPrivileges(token, false, ref tp,
                (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
        }
        finally { CloseHandle(token); }
    }
}
'@
}

# 默认就要操作 ACE 进程，故默认启用调试特权；只有 -NoTune（仅启动客户端）时不启用。
if ($NeedsPrivilege) {
    [SGuardNative]::EnablePrivilege('SeDebugPrivilege') | Out-Null
}

# 以“非管理员”身份启动进程（从已登录的 explorer 令牌降权），用于在不提权的前提下拉起游戏客户端，
# 避免以管理员运行游戏被 ACE / COM 误判为环境异常。
if (-not ('NonElevated' -as [type])) {
    Add-Type -Language CSharp @'
using System;
using System.Runtime.InteropServices;
public static class NonElevated {
  [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr GetShellWindow();
  [DllImport("user32.dll", SetLastError=true)] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint dwAccess, bool bInheritHandle, uint dwProcessId);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
  [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)] public struct STARTUPINFO { public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
  public static bool Launch(string app, string args) {
    IntPtr hwnd = GetShellWindow();
    if (hwnd == IntPtr.Zero) return false;
    uint pid; GetWindowThreadProcessId(hwnd, out pid);
    IntPtr hProc = OpenProcess(0x0400, false, pid);
    if (hProc == IntPtr.Zero) return false;
    try {
      IntPtr hToken;
      if (!OpenProcessToken(hProc, 0x0008 | 0x0010, out hToken)) return false;
      try {
        IntPtr hNew;
        if (!DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hNew)) return false;
        try {
          STARTUPINFO si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)); si.wShowWindow = 1;
          PROCESS_INFORMATION pi;
          string cmd = "\"" + app + "\" " + args;
          return CreateProcessWithTokenW(hNew, 0, null, cmd, 0, IntPtr.Zero, null, ref si, out pi);
        } finally { CloseHandle(hNew); }
      } finally { CloseHandle(hToken); }
    } finally { CloseHandle(hProc); }
  }
}
'@
}

# ---------- 环境校验 ----------
$cpuCount = [Environment]::ProcessorCount
if ($Cpu -lt 0 -or $Cpu -ge $cpuCount) {
    Write-Log ("CPU 编号 {0} 无效：本机逻辑处理器数量为 {1}，可用范围 0-{2}" -f $Cpu, $cpuCount, ($cpuCount - 1)) 'ERROR'
    exit 1
}
$mask = [uint64]1 -shl $Cpu

$prioClass = switch ($Priority) {
    'Idle'        { [uint32]0x00000040 }
    'BelowNormal' { [uint32]0x00004000 }
    'Normal'      { [uint32]0x00000020 }
}
$prioText = switch ($Priority) {
    'Idle'        { '低 (Idle)' }
    'BelowNormal' { '低于正常 (BelowNormal)' }
    'Normal'      { '正常 (Normal)' }
}

function Get-MaskCpus {
    param([uint64]$Mask)
    if ($Mask -eq 0) { return '0' }
    $list = @()
    for ($i = 0; $i -lt 64; $i++) {
        if (($Mask -shr $i) -band 1) { $list += "CPU $i" }
    }
    return ($list -join ', ')
}

function Get-PrioText {
    param([uint32]$Class)
    switch ($Class) {
        0x00000040 { '低' }
        0x00004000 { '低于正常' }
        0x00000020 { '正常' }
        0x00008000 { '高于正常' }
        0x00000080 { '高' }
        0x00000100 { '实时' }
        default    { ('0x{0:X}' -f $Class) }
    }
}

function Get-TargetProc {
    $found = @()
    foreach ($n in $ProcessNames) {
        $found += @(Get-Process -Name $n -ErrorAction SilentlyContinue)
    }
    return $found
}

function Get-CurrentState {
    param([int]$ProcessId)
    $h = [SGuardNative]::OpenProcess(0x0400, $false, $ProcessId)
    if ($h -eq [IntPtr]::Zero) {
        return [pscustomobject]@{ Ok = $false; Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error(); Prio = 0; Mask = [uint64]0 }
    }
    try {
        return [pscustomobject]@{
            Ok    = $true
            Error = 0
            Prio  = [SGuardNative]::GetPriorityClass($h)
            Mask  = [uint64][SGuardNative]::GetAffinity($h)
        }
    } finally { [SGuardNative]::CloseHandle($h) | Out-Null }
}

function Set-TargetState {
    param([int]$ProcessId)
    $h = [SGuardNative]::OpenProcess(0x0400 -bor 0x0200, $false, $ProcessId)
    if ($h -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        return [pscustomobject]@{ Ok = $false; Error = $err; PrioOk = $false; AffOk = $false }
    }
    try {
        $prioOk = [SGuardNative]::SetPriorityClass($h, $prioClass)
        $prioErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $affOk = [SGuardNative]::SetAffinity($h, $mask)
        $affErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        return [pscustomobject]@{
            Ok     = ($prioOk -and $affOk)
            Error  = if (-not $prioOk) { $prioErr } elseif (-not $affOk) { $affErr } else { 0 }
            PrioOk = $prioOk
            AffOk  = $affOk
        }
    } finally { [SGuardNative]::CloseHandle($h) | Out-Null }
}

# ---------- 客户端启动 ----------
# 直接启动 LeagueClient.exe 的兜底路径（默认走 startup_runner.exe；直启仅作最后兜底，可能被 ACE 拦截）。
function Resolve-Shortcut {
    if ($Shortcut -and (Test-Path -LiteralPath $Shortcut)) { return $Shortcut }
    $candidates = @(
        'D:\Software\英雄联盟(26)\LeagueClient\LeagueClient.exe',
        'D:\Software\英雄联盟(26)\Launcher\startup_runner.exe',
        'D:\Software\英雄联盟(26)\Launcher\Client.exe'
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}

# 查找英雄联盟客户端（非 WeGame）——默认优先腾讯官方启动器 startup_runner.exe，
# 它负责拉起 Riot 客户端与游戏本体，ACE 信任该启动链（与桌面“英雄联盟”快捷方式一致）。
function Find-Client {
    $candidates = @(
        'D:\Software\英雄联盟(26)\Launcher\startup_runner.exe',
        'D:\Software\英雄联盟(26)\Riot Client\RiotClientServices.exe',
        'D:\Software\英雄联盟(26)\LeagueClient\LeagueClient.exe'
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    # 兜底：允许用户用 -Shortcut 指定（例如桌面原英雄联盟快捷方式）
    if ($Shortcut -and (Test-Path -LiteralPath $Shortcut)) { return $Shortcut }
    return $null
}

# 启动英雄联盟：走腾讯官方启动器 startup_runner.exe 启动链（非 WeGame），并以普通用户身份拉起，避免被 ACE 判定为环境异常。
# 若本脚本被以管理员身份运行（例如给快捷方式勾了“以管理员身份运行”），则自动降权拉起。
function Start-Client {
    $client = Find-Client
    if (-not $client) {
        Write-Log '未找到英雄联盟客户端（startup_runner.exe / RiotClientServices.exe / LeagueClient.exe），请确认游戏安装路径，或用 -Shortcut 指定。' 'ERROR'
        exit 1
    }
    $wd = Split-Path -Parent $client
    Write-Log ("启动客户端（腾讯官方启动器，非 WeGame）：{0}" -f $client)
    if (Test-Admin) {
        # 以管理员运行游戏会被 ACE 判定为“环境异常”，降权为普通用户拉起
        $ok = $false
        try { $ok = [NonElevated]::Launch($client, '') } catch { $ok = $false }
        if (-not $ok) {
            Write-Log '降权启动失败，回退到普通方式（若仍报 ACE 安全组件异常，请勿以管理员身份运行本脚本）。' 'WARN'
            Start-Process -FilePath $client -WorkingDirectory $wd | Out-Null
        }
    } else {
        Start-Process -FilePath $client -WorkingDirectory $wd | Out-Null
    }
}

# ---------- 状态模式 ----------
if ($Status) {
    $procs = Get-TargetProc
    if (-not $procs) { Write-Log '未找到 SGuard 进程（客户端未启动？）' 'WARN'; exit 0 }
    Write-Host ''
    Write-Host ('{0,-8} {1,-18} {2,-12} {3}' -f 'PID', '进程', '优先级', '相关性') -ForegroundColor Cyan
    foreach ($p in $procs) {
        $st = Get-CurrentState -ProcessId $p.Id
        if ($st.Ok) {
            Write-Host ('{0,-8} {1,-18} {2,-12} {3}' -f $p.Id, $p.ProcessName, (Get-PrioText $st.Prio), (Get-MaskCpus $st.Mask))
        } else {
            Write-Host ('{0,-8} {1,-18} 无法读取(错误码 {2})，请以管理员运行' -f $p.Id, $p.ProcessName, $st.Error) -ForegroundColor Yellow
        }
    }
    Write-Host ''
    exit 0
}

# ---------- 启动客户端 ----------
$clientProcNames = @('LeagueClient', 'LeagueClientUx', 'League of Legends', 'RiotClientServices', 'startup_runner')
$clientRunning = @(Get-Process -Name $clientProcNames -ErrorAction SilentlyContinue).Count -gt 0

if (-not $NoLaunch) {
    if ($clientRunning) {
        Write-Log '检测到客户端已在运行，跳过启动。'
    } else {
        Start-Client
    }
}

# ---------- 是否执行 SGuard 优化（默认开启；加 -NoTune 则只启动客户端） ----------
if ($NoTune) {
    Write-Log '已指定 -NoTune：本脚本仅负责启动客户端，不会修改 SGuard 的优先级/相关性。' 'INFO'
    Write-Log '客户端已启动，可关闭本窗口。'
    exit 0
}

# ---------- 等待 SGuard 出现 ----------
if (@(Get-TargetProc).Count -eq 0) {
    Write-Log ("等待 SGuard 进程出现（最多 {0} 秒）..." -f $WaitSeconds)
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        if (@(Get-TargetProc).Count -gt 0) { break }
        Start-Sleep -Milliseconds 500
    }
}

# ---------- 应用 / 守护 ----------
$state = @{}          # PID -> @{ Prio; Mask }
$failCount = @{}      # PID -> 连续失败次数
$noTargetSince = $null
$appliedAny = $false

while ($true) {
    $procs = Get-TargetProc

    if (-not $procs) {
        if ($null -eq $noTargetSince) { $noTargetSince = Get-Date }
        $goneFor = ((Get-Date) - $noTargetSince).TotalSeconds
        if ($appliedAny -and $goneFor -gt 120) {
            $stillClient = @(Get-Process -Name $clientProcNames -ErrorAction SilentlyContinue).Count -gt 0
            if (-not $stillClient) {
                Write-Log 'ACE 进程与客户端均已退出，守护结束。'
                break
            }
        }
    } else {
        $noTargetSince = $null
        foreach ($p in $procs) {
            $key = $p.Id
            $cur = Get-CurrentState -ProcessId $p.Id

            if ($cur.Ok -and $cur.Prio -eq $prioClass -and $cur.Mask -eq $mask) {
                if (-not $state.ContainsKey($key)) {
                    $state[$key] = @{ Prio = $cur.Prio; Mask = $cur.Mask }
                    Write-Log ("{0}(PID {1}) 已确认：优先级 {2}，相关性 {3}" -f $p.ProcessName, $p.Id, (Get-PrioText $cur.Prio), (Get-MaskCpus $cur.Mask)) 'OK'
                }
            }
            else {
                $r = Set-TargetState -ProcessId $p.Id
                if ($r.Ok) {
                    $state[$key] = @{ Prio = $prioClass; Mask = $mask }
                    $failCount.Remove($key)
                    $appliedAny = $true
                    Write-Log ("{0}(PID {1}) 已设置：优先级 {2}，相关性 仅 CPU {3}" -f $p.ProcessName, $p.Id, (Get-PrioText $prioClass), $Cpu) 'OK'
                } else {
                    $n = 1 + [int]($failCount[$key])
                    $failCount[$key] = $n
                    if ($n -le 3 -or ($n % 30) -eq 0) {
                        $hint = if ($r.Error -eq 5) { '（拒绝访问：请确认脚本以管理员身份运行；若已是管理员仍报此错，说明该进程被 ACE 自我保护拦住，只能手动在任务管理器里设置）' } else { '' }
                        Write-Log ("{0}(PID {1}) 设置失败，错误码 {2}（优先级成功={3}，相关性成功={4}）{5}" -f $p.ProcessName, $p.Id, $r.Error, $r.PrioOk, $r.AffOk, $hint) 'ERROR'
                    }
                }
            }
        }
        # 清理已退出的 PID
        foreach ($k in @($state.Keys)) {
            if (-not ($procs | Where-Object { $_.Id -eq $k })) { $state.Remove($k); $failCount.Remove($k) }
        }
    }

    if ($Once) { break }
    Start-Sleep -Milliseconds $IntervalMs
}

if ($Once) {
    $procs = Get-TargetProc
    if (-not $procs) { Write-Log '未找到 SGuard 进程，未做任何修改。' 'WARN'; exit 2 }
    $ok = ($state.Count -gt 0)
    exit ([int](-not $ok))
}
