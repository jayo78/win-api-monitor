#pragma once

// standard information for every hook
struct HOOK_INFO {
    LPCWSTR lib;
    LPCSTR target;
    LPVOID proxy;
    LPVOID fp;
};

// Proxy Function Definitions
//============================================

typedef int (WINAPI *CONNECT)(SOCKET, const SOCKADDR*, int);
typedef int (WINAPI *CREATEPROCESSINTERNALW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
typedef int (WINAPI *LOADLIBRARYEXW)(LPCWSTR, HANDLE, DWORD);
typedef int (WINAPI *LOADLIBRARYW)(LPCWSTR);
typedef int (WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);


// Trampoline Function Declarations
//============================================

GETPROCADDRESS fpGetProcAddress= NULL;
LOADLIBRARYA fpLoadLibraryA= NULL;
LOADLIBRARYW fpLoadLibraryW= NULL;
LOADLIBRARYEXW fpLoadLibraryExW= NULL;
CONNECT fpConnect= NULL;
CREATEPROCESSINTERNALW fpCreateProcessInternalW= NULL;


// Proxy Functions 
//============================================

int WINAPI ProxyConnect(SOCKET s, const sockaddr* name, int namelen)
{
    /*
    ** dynamically loading the WSAAddressToStringW function from the ws2_32 dll in order to 
    ** resolve a standard IP dot notation from the sockaddr struct. uses GetModuleHandle so the 
    ** ws2_32 dll isn't loaded if the target process isn't using it (no need to hook in that case)
    */
    typedef int (WINAPI *WSAADDRESSTOSTRINGW)(LPSOCKADDR, DWORD, LPDWORD, LPWSTR, LPDWORD);
    HMODULE hModule= GetModuleHandle("ws2_32");
    WSAADDRESSTOSTRINGW WSAAddressToStringW= (WSAADDRESSTOSTRINGW) GetProcAddress(hModule, "WSAAddressToStringW");

    wchar_t addr[32];
    DWORD sz= 32;
    WSAAddressToStringW((SOCKADDR *)name, namelen, NULL, addr, &sz);

    std::wcout << L"[HOOK] Intercepted call to connect:\n" << L"- IP Address: " << addr << std::endl;
    return fpConnect(s, name, namelen);
}

int WINAPI ProxyCreateProcessInternalW
    (HANDLE hToken,  
    LPCWSTR lpApplicationName, 
    LPWSTR lpCommandLine, 
    LPSECURITY_ATTRIBUTES lpProcessAttributes, 
    LPSECURITY_ATTRIBUTES lpThreadAttributes, 
    BOOL bInheritHandles, 
    DWORD dwCreationFlags, 
    LPVOID lpEnvironment, 
    LPCWSTR lpCurrentDirectory, 
    LPSTARTUPINFOW lpStartupInfo, 
    LPPROCESS_INFORMATION lpProcessInformation, 
    PHANDLE hNewToken)
{
    std::wcout << L"[HOOK] Intercepted call to CreateProcessInternalW:\n" << L"- Application Name: " << lpCommandLine << std::endl;
    return fpCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
}

int WINAPI ProxyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    std::wcout << L"[HOOK] Intercepted call to LoadLibraryExW:\n" << L"- Library Name: " << lpLibFileName << std::endl;
    return fpLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

int WINAPI ProxyLoadLibraryW(LPCWSTR lpLibFileName)
{
    std::wcout << L"[HOOK] Intercepted call to LoadLibraryW:\n" << L"- Library Name: " << lpLibFileName << std::endl;
    return fpLoadLibraryW(lpLibFileName);
}

int WINAPI ProxyLoadLibraryA(LPCSTR lpLibFileName)
{
    wchar_t wLibName[128];
    MultiByteToWideChar(CP_THREAD_ACP, (DWORD)0, lpLibFileName, -1, wLibName, 128);
    std::wcout << L"[HOOK] Intercepted call to LoadLibraryA:\n" << L"- Library Name: " << wLibName << std::endl;
    return fpLoadLibraryA(lpLibFileName);
}

FARPROC WINAPI ProxyGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    wchar_t wProcName[128];
    MultiByteToWideChar(CP_THREAD_ACP, (DWORD)0, lpProcName, -1, wProcName, 128);
    std::wcout << L"[HOOK] Intercepted call to GetProcAddress:\n" << L"- Function Name: " << wProcName << std::endl;
    return fpGetProcAddress(hModule, lpProcName);
}







