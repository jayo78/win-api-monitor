### Description

This is a basic API monitoring program for running windows executables and intercepting their calls to the WinAPI. It uses minhook as an inline hooking engine and DLL injection as the process injection technique.

#### injector

The injector uses DLL injection and may be flagged by AV as it uses common API calls found in malware injection. 

- Creates target process as suspended
- Writes to process space with VirtualAlloc and WriteProcessMemory
- Executes remote thread to load the monitor DLL and install hooks
- Resumes target thread after hooks have been installed

#### monitor

The monitor, once injected, installs hooks that report intercepted calls made by the injected process. **Compilation:** use `/LD` (MSVC compiler) to create as a DLL. The monitor depends on [minhook](https://github.com/TsudaKageyu/minhook) so be sure to link that library and use the minhook.h header.

