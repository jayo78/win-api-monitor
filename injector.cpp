#include <windows.h>
#include <iostream>
#include <tchar.h>

void inject_DLL(TCHAR *dllPath, HANDLE process)
{
    LPVOID lpBaseAddress;
    HANDLE hRemoteThread;
    HMODULE kernel32;
    FARPROC loadlibrary;
    SIZE_T pathLen;
    
    lpBaseAddress= NULL;
    hRemoteThread= NULL;
    loadlibrary= NULL; 
    kernel32= NULL;
    pathLen= _tcslen(dllPath) * sizeof(TCHAR);

    kernel32= GetModuleHandle(_T("kernel32.dll"));
    loadlibrary= GetProcAddress(kernel32, _T("LoadLibraryA"));

// Allocate memory and write the dll path that will be injected
    lpBaseAddress= VirtualAllocEx(process, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBaseAddress == NULL)
        std::cout << "VirtualAllocEx failed: " << GetLastError() << std::endl;
    
    if (!WriteProcessMemory(process, lpBaseAddress, dllPath, pathLen, NULL))
        std::cout << "WriteProcessMemory failed: " << GetLastError() << std::endl;

// Create a thread that will load the dll path using LoadLibrary as a start up routine 
    hRemoteThread= CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(VOID *)loadlibrary, lpBaseAddress, NULL, 0);
    if (hRemoteThread == NULL)
        std::cout << "CreateRemoteThread failed: " << GetLastError() << std::endl;

    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
}

int main(int argc, TCHAR *argv[])
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR *targetExe;
    TCHAR *dllName;
    TCHAR dllPath[MAX_PATH];
    SIZE_T pathLen;

    if (argc < 3)
    {
        std::cout << "Not enough arguments\n" << "Usage: injector.exe <target> <dll>\n";
        return 1;
    }
        
    targetExe= _T(argv[1]);
    dllName= _T(argv[2]);
    GetFullPathName(dllName, MAX_PATH, dllPath, NULL);

    ZeroMemory( &si, sizeof(si));
    ZeroMemory( &pi, sizeof(pi));
    si.cb = sizeof(si);

// Create the process as suspended - main thread created but no DLLs loaded
    if(!CreateProcess(NULL, targetExe, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) 
    {
        std::cout << "CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

// inject the process that we created 
    inject_DLL(dllPath, pi.hProcess);

// Resume the suspended process now with our DLL injected
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}