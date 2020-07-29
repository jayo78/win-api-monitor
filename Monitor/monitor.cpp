#include <windows.h>
#include <iostream>
#include "MinHook.h"
#include "monitor.h"
#include "logger.h"

#pragma comment(lib, "libMinHook-x86mt.lib")


// Hooks that will be installed (see monitor.h)
//============================================

HOOK_INFO hooks[]= {
    {
        L"ws2_32",
        "connect",
        &ProxyConnect,
        &fpConnect
    },
    {
        L"kernelbase",
        "CreateProcessInternalW",
        &ProxyCreateProcessInternalW,
        &fpCreateProcessInternalW
    },
    {
        L"kernel32",
        "LoadLibraryExW",
        &ProxyLoadLibraryExW,
        &fpLoadLibraryExW
    },
    {
        L"kernel32",
        "LoadLibraryW",
        &ProxyLoadLibraryW,
        &fpLoadLibraryW
    },
    {
        L"kernel32",
        "LoadLibraryA",
        &ProxyLoadLibraryA,
        &fpLoadLibraryA
    },
    {
        L"kernel32", 
        "GetProcAddress",
        &ProxyGetProcAddress,
        &fpGetProcAddress
    }
};


// Hook installation functions
//============================================

__forceinline BOOL install_hook(HOOK_INFO *pHookInfo)
{
    if (MH_CreateHookApi(pHookInfo->lib, pHookInfo->target, pHookInfo->proxy, (LPVOID *)(pHookInfo->fp)) != MH_OK)
        return FALSE;

    return TRUE;
}

VOID install_all()
{
    int numElts= sizeof(hooks)/sizeof(hooks[0]);

    for (int i= 0; i < numElts; i++)
    {
        if (install_hook(&hooks[i]))
            logger << L"[+] Installed hook in: " << hooks[i].target << "\n";
    }
}


// DLL entry 
//============================================

BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)  
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            logger << L"[+] Installing hooks...\n";

            MH_Initialize();
            install_all();
            MH_EnableHook(MH_ALL_HOOKS);

            logger << L"[+] Hooks installed, Resuming main thread..." << std::endl;
            break;

        case DLL_PROCESS_DETACH:
            Sleep(7000);
            break;
    }

    return TRUE;  
}

