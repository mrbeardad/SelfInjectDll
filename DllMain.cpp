#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <process.h>

#include <string>

static LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

extern "C" __declspec(dllexport) void CALLBACK Inject(HWND hwnd, HINSTANCE hinst, LPSTR pszCmdLine, int nCmdShow)
{
//#define TARGET_PROCESS_NAME "TargetProcessName.exe"
    // Get wstring processName
#ifdef TARGET_PROCESS_NAME
    LPCSTR szProcessName = TARGET_PROCESS_NAME;
    size_t length = ::strlen(TARGET_PROCESS_NAME);
#else
    LPCSTR szProcessName = pszCmdLine;
    size_t length = ::strlen(pszCmdLine);
#endif
    std::wstring processName;
    int size = ::MultiByteToWideChar(CP_ACP, 0, szProcessName, length, NULL, 0);
    processName.resize(size);
    ::MultiByteToWideChar(CP_ACP, 0, szProcessName, length, processName.data(), size);

    // Search the process
    DWORD pid = 0;
    {
        HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return;
        }
        PROCESSENTRY32W entry{sizeof(PROCESSENTRY32W)};
        if (::Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (entry.th32ProcessID > 0 && ::_wcsicmp(entry.szExeFile, processName.c_str()) == 0)
                {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (::Process32NextW(snapshot, &entry));
        }
        ::CloseHandle(snapshot);
    }
    if (pid == 0)
    {
        ::wprintf(L"ERROR: process %s not found\n", processName.c_str());
        return;
    }

    // Search the UI thread then inject Windows Hook
    {
        HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return;
        }
        THREADENTRY32 entry{sizeof(THREADENTRY32)};
        if (::Thread32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID == pid)
                {
                    if (::SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)GetMsgProc, (HINSTANCE)&__ImageBase, entry.th32ThreadID))
                    {
                        // Sleep for a while to insure there is enough time to inject dll
                        for (int i = 0; i < 3; i++)
                        {
                            ::PostThreadMessageW(entry.th32ThreadID, WM_NULL, NULL, NULL);
                            ::Sleep(500);
                        }
                        break;
                    }
                }
            } while (::Thread32Next(snapshot, &entry));
        }
        ::CloseHandle(snapshot);
    }
}

static BOOL IsRunDll32()
{
    WCHAR wszBaseName[MAX_PATH]{};
    ::GetModuleBaseNameW(::GetCurrentProcess(), NULL, wszBaseName, sizeof(wszBaseName) / sizeof(WCHAR));
    return ::_wcsicmp(wszBaseName, L"rundll32.exe") == 0;
}

static unsigned WINAPI MainThread(LPVOID)
{
    __try
    {
        for (int count = 0; count < 10; count++)
        {
            ::system("echo My dll has been loaded. && pause");
            break;
            ::Sleep(500);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ::OutputDebugStringW(L"===== EXCEPTION ERROR");
    }
    return 0;
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hMod);
        if (!IsRunDll32())
        {
            // Dll will been unloaded after the thread end
            ::_beginthreadex(NULL, 0, MainThread, NULL, 0, NULL);
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
