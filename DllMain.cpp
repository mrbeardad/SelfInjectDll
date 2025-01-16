#include <memory>
#include <string>

#include <process.h>
#include <psapi.h>
#include <tlhelp32.h>

DWORD FindProcessByName(char* szProcessName)
{
    DWORD cbNeeded = 0;
    DWORD piProcesses[2048];
    if (!EnumProcesses(piProcesses, sizeof(piProcesses), &cbNeeded)) {
        return 0;
    }

    int iNumEnumeratedProcesses = cbNeeded / sizeof(DWORD);
    for (int i = 0; i < iNumEnumeratedProcesses; i++) {
        DWORD pid = piProcesses[i];

        typedef std::shared_ptr<void> SafeHandle;
        SafeHandle hProcess = SafeHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), [](HANDLE hHandleToClose) {
            if (hHandleToClose != NULL) {
                CloseHandle(hHandleToClose);
            }
        });

        if (hProcess != NULL) {
            CHAR szProcessPath[MAX_PATH] {};
            DWORD size = MAX_PATH;
            if (!QueryFullProcessImageNameA(hProcess.get(), 0, szProcessPath, &size)) {
                continue;
            }
            char* sep = ::strrchr(szProcessPath, '\\');
            if (!sep) {
                continue;
            }
            if (::_stricmp(sep + 1, szProcessName) == 0) {
                return pid;
            }
        }
    }

    return 0;
}

LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

extern "C" __declspec(dllexport) void CALLBACK Inject(HWND hwnd,
    HINSTANCE hinst,
    LPSTR pszCmdLine,
    int nCmdShow)
{
    auto hb = &__ImageBase;
    DWORD pid = FindProcessByName(pszCmdLine);
    if (pid == 0) {
        printf("ERROR: process %s not found\n", pszCmdLine);
        return;
    }
    HANDLE h = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(h, &te)) {
            do {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID) && te.th32OwnerProcessID == pid) {
                    if (::SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)GetMsgProc, (HINSTANCE)&__ImageBase, te.th32ThreadID)) {
                        // Sleep for a while to insure there is enough time to inject dll
                        for (int i = 0; i < 10; i++) {
                            ::PostThreadMessage(te.th32ThreadID, WM_NULL, NULL, NULL);
                            Sleep(500);
                        }
                        break;
                    }
                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
}

BOOL IsRunDll32()
{
    CHAR szMainModulePath[MAX_PATH];
    DWORD dwMainModulePathLength = ::GetModuleFileNameA(NULL, szMainModulePath, sizeof(szMainModulePath));
    return dwMainModulePathLength > 13 && ::_stricmp(szMainModulePath + dwMainModulePathLength - 13, "\\rundll32.exe") == 0;
}

unsigned WINAPI MainThread(LPVOID)
{
    ::system("echo My dll has been loaded. && pause");
    return 0;
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hMod);
        if (!IsRunDll32()) {
            // Dll will been unloaded after the thread end
            // ::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)hMod, &hMod);
            ::_beginthreadex(NULL, 0, MainThread, NULL, 0, NULL);
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
