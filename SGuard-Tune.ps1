<#
.SYNOPSIS
    启动英雄联盟客户端，并把 SGuard64.exe / SGuard64Svc64.exe 的优先级设为「低」、
    CPU 相关性设为「仅 CPU 3」（可在任务管理器 - 详细信息 中看到效果）。

.DESCRIPTION
    ACE(SGuard) 会以 SYSTEM 身份运行、且会自我重启，因此本脚本：
      1) 自动提权到管理员（否则无法操作 SYSTEM 进程）
      2) 用 explorer 以普通权限启动客户端（避免游戏被跟着提权）
      3) 轮询等待 SGuard 进程出现，逐个设置 Idle 优先级 + 单核亲和性
      4) 持续守护：进程重启 / 设置被重置时自动重新应用
      5) 自己退出时不影响游戏；Ctrl+C 停止守护即可

.PARAMETER Cpu
    目标 CPU 编号（0 基）。默认 3 → 即任务管理器里的 CPU 3（第 4 个逻辑核）。

.PARAMETER Priority
    优先级：Idle(低，默认) / BelowNormal / Normal

.PARAMETER NoLaunch
    不启动客户端，只对已在运行的进程生效。

.PARAMETER Once
    只应用一次并退出（不常驻守护）。

    .PARAMETER Status
    只查看当前 SGuard 进程的优先级与相关性，不做任何修改。

.PARAMETER StoreCredential
    一次性把 QQ 号与密码安全存入 Windows 凭据管理器（屏幕不回显），随后退出。
    之后无需再在脚本里写任何明文。

.PARAMETER AutoLogin
    客户端启动后自动填入已保存的 QQ 与密码（UI 自动化优先，失败退回模拟键盘）。
    双击启动批处理默认带此开关。

.PARAMETER QQ
    指定要填入的 QQ 号（不指定则用凭据管理器里保存的账号）。仅与 -AutoLogin 配合。

.PARAMETER CredTarget
    凭据在 Windows 凭据管理器中的目标名，默认 SGuardTune_LoL。

.PARAMETER LoginWaitMs / FillDelayMs
    登录框出现前的等待时间 / 填表前的对焦延迟（毫秒），机器慢可调大。

.EXAMPLE
    .\SGuard-Tune.ps1
    .\SGuard-Tune.ps1 -Cpu 3 -NoLaunch
    .\SGuard-Tune.ps1 -Status
    .\SGuard-Tune.ps1 -StoreCredential      # 第一次运行，保存 QQ+密码
    .\SGuard-Tune.ps1 -AutoLogin             # 启动并自动登录
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
    [switch]$Status,
    [string]$QQ,
    [switch]$StoreCredential,
    [switch]$AutoLogin,
    [string]$CredTarget = 'SGuardTune_LoL',
    [int]$LoginWaitMs = 20000,
    [int]$FillDelayMs = 800
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

if (-not (Test-Admin)) {
    Write-Host '需要管理员权限，正在请求提权...' -ForegroundColor Yellow
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

[SGuardNative]::EnablePrivilege('SeDebugPrivilege') | Out-Null

# ---------- 凭据安全存储（Windows 凭据管理器，不落明文） ----------
if (-not ('CredStore' -as [type])) {
    Add-Type -Language CSharp @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class CredStore {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public uint Flags; public uint Type; public string TargetName; public string Comment;
    public FILETIME LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob;
    public uint Persist; public uint AttributeCount; public IntPtr Attributes;
    public string TargetAlias; public string UserName;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct FILETIME { public uint Low; public uint High; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWrite(ref CREDENTIAL c, uint flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredRead(string target, uint type, uint flags, out IntPtr pc);
  [DllImport("advapi32.dll")]
  static extern void CredFree(IntPtr p);
  const uint CRED_TYPE_GENERIC = 1;
  const uint CRED_PERSIST_LOCAL_MACHINE = 2;
  public static bool Write(string target, string user, string pass, uint persist = CRED_PERSIST_LOCAL_MACHINE) {
    byte[] bytes = Encoding.Unicode.GetBytes(pass);
    CREDENTIAL c = new CREDENTIAL();
    c.Type = CRED_TYPE_GENERIC; c.TargetName = target; c.Comment = "LoL auto-login";
    IntPtr p = Marshal.AllocHGlobal(bytes.Length);
    Marshal.Copy(bytes, 0, p, bytes.Length);
    c.CredentialBlob = p; c.CredentialBlobSize = (uint)bytes.Length;
    c.Persist = persist; c.UserName = user;
    c.AttributeCount = 0; c.Attributes = IntPtr.Zero;
    bool ok = CredWrite(ref c, 0);
    Marshal.FreeHGlobal(p);
    return ok;
  }
  public static string Read(string target, out string user) {
    IntPtr pc; user = null;
    if (!CredRead(target, CRED_TYPE_GENERIC, 0, out pc)) return null;
    try {
      CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(pc, typeof(CREDENTIAL));
      byte[] b = new byte[c.CredentialBlobSize];
      Marshal.Copy(c.CredentialBlob, b, 0, (int)c.CredentialBlobSize);
      user = c.UserName;
      return Encoding.Unicode.GetString(b);
    } finally { CredFree(pc); }
  }
}
'@
}

if (-not ('User32' -as [type])) {
    Add-Type -Language CSharp @'
using System;
using System.Runtime.InteropServices;
public static class User32 {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool AllowSetForegroundWindow(int pid);
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] p, int cb);
  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

  [StructLayout(LayoutKind.Sequential)]
  public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr extra;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct INPUT { public uint type; public KEYBDINPUT ki; }

  // 以 Unicode 方式输入字符串，可输入任意字符（含中文、特殊符号），无需 WinForms
  public static int SendUnicode(string s) {
    if (string.IsNullOrEmpty(s)) return 0;
    INPUT[] inputs = new INPUT[s.Length * 2];
    for (int i = 0; i < s.Length; i++) {
      ushort c = (ushort)s[i];
      inputs[i * 2]     = new INPUT { type = 1, ki = new KEYBDINPUT { wScan = c, dwFlags = 4 } };        // KEYEVENTF_UNICODE
      inputs[i * 2 + 1] = new INPUT { type = 1, ki = new KEYBDINPUT { wScan = c, dwFlags = 4 | 2 } };    // +KEYEVENTF_KEYUP
    }
    return (int)SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
  }
  public static void SendVk(ushort vk) {
    keybd_event((byte)vk, 0, 0, UIntPtr.Zero);
    keybd_event((byte)vk, 0, 2, UIntPtr.Zero);
  }
}
'@
}

function Set-LoginCredential {
    $qq = Read-Host '请输入 QQ 号'
    if (-not $qq) { Write-Log 'QQ 号为空，已取消。' 'WARN'; return $false }
    $sec = Read-Host '请输入密码（输入时屏幕不显示）' -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    $ok = [CredStore]::Write($CredTarget, $qq, $plain)
    if ($ok) { Write-Log ("已安全保存凭据到 Windows 凭据管理器（目标名 {0}）" -f $CredTarget) 'OK' }
    else { Write-Log ('凭据保存失败，错误码 ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) 'ERROR' }
    return $ok
}

function Get-LoginCredential {
    $user = $null
    $pass = [CredStore]::Read($CredTarget, [ref]$user)
    if ($null -eq $pass) { return $null }
    if ($QQ) { $user = $QQ }
    return @{ QQ = $user; Password = $pass }
}

function Invoke-AutoLogin {
    param($Credential)
    Write-Log '等待客户端登录窗口...'
    Start-Sleep -Milliseconds $LoginWaitMs
    $proc = @(Get-Process -Name 'LeagueClientUx', 'LeagueClient' -ErrorAction SilentlyContinue) |
        Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if (-not $proc) {
        Write-Log '未找到客户端登录窗口，跳过自动填充（可能已登录，或窗口标题不同）。' 'WARN'
        return
    }
    [User32]::AllowSetForegroundWindow($proc.Id) | Out-Null
    [User32]::ShowWindow($proc.MainWindowHandle, 9) | Out-Null
    [User32]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
    Start-Sleep -Milliseconds $FillDelayMs

    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName UIAutomationClient -ErrorAction SilentlyContinue
    Add-Type -AssemblyName UIAutomationTypes -ErrorAction SilentlyContinue

    $usedUi = $false
    try {
        $cond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Edit)
        $root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
        $edits = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
        if ($edits.Count -ge 2) {
            $e0 = $edits[0].GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
            $e0.SetValue($Credential.QQ)
            Start-Sleep -Milliseconds 250
            $e1 = $edits[1].GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
            $e1.SetValue($Credential.Password)
            Write-Log '已通过 UI 自动化填入账号与密码。' 'OK'
            $usedUi = $true
        }
    } catch { $usedUi = $false }

    if (-not $usedUi) {
        Write-Log 'UI 自动化不可用（登录框通常是网页/CEF 控件），回退到模拟键盘输入。' 'WARN'
        try {
            [User32]::SendUnicode($Credential.QQ)
            Start-Sleep -Milliseconds 300
            [User32]::SendVk(9)   # Tab
            Start-Sleep -Milliseconds 200
            [User32]::SendUnicode($Credential.Password)
            Start-Sleep -Milliseconds 200
            [User32]::SendVk(13)  # Enter
            Write-Log '已通过模拟键盘输入账号、密码并回车。' 'OK'
        } catch {
            Write-Log ('自动输入失败：' + $_.Exception.Message + '（请手动输入）') 'ERROR'
        }
    }
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
function Resolve-Shortcut {
    if ($Shortcut -and (Test-Path -LiteralPath $Shortcut)) { return $Shortcut }
    $candidates = @(
        'D:\Software\英雄联盟(26)\Launcher\startup_runner.exe',
        'D:\Software\英雄联盟(26)\LeagueClient\LeagueClient.exe'
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}

# ---------- 仅保存凭据 ----------
if ($StoreCredential) {
    Set-LoginCredential | Out-Null
    Write-Log '凭据已保存：以后直接双击启动批处理（带 -AutoLogin）即可自动填入。'
    exit 0
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
Write-Log ("目标：优先级 = {0}，相关性 = 仅 CPU {1}（掩码 0x{2:X}）" -f $prioText, $Cpu, $mask)

$clientProcNames = @('LeagueClient', 'LeagueClientUx', 'League of Legends', 'startup_runner', 'wegame')
$clientRunning = @(Get-Process -Name $clientProcNames -ErrorAction SilentlyContinue).Count -gt 0

if (-not $NoLaunch -and -not $Once) {
    if ($clientRunning) {
        Write-Log '检测到客户端已在运行，跳过启动。'
    } else {
        $target = Resolve-Shortcut
        if (-not $target) {
            Write-Log '未找到英雄联盟快捷方式，请用 -Shortcut 指定路径。' 'ERROR'
            exit 1
        }
        Write-Log ("启动客户端：{0}" -f $target)
        # 用 explorer 启动，继承普通用户权限，避免游戏被一起提权
        Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$target`""
    }
}

# ---------- 自动登录 ----------
if ($AutoLogin) {
    $cred = Get-LoginCredential
    if ($cred) { Invoke-AutoLogin -Credential $cred }
    else { Write-Log '未找到已保存的登录凭据，请先运行一次 -StoreCredential 保存 QQ 与密码。' 'WARN' }
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
