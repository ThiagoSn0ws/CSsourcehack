#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <wchar.h>

using Address = std::uintptr_t;
const wchar_t* targetProcess = L"cstrike_win64.exe";           


Address GetModuleBaseAddress(const wchar_t* processName, const wchar_t* moduleName) {
    DWORD procId = 0;
    Address modBaseAddr = 0;
    HANDLE hSnap = INVALID_HANDLE_VALUE;
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32FirstW(hSnap, &procEntry)) {
            do {
                if (!_wcsicmp(procEntry.szExeFile, processName)) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &procEntry));
        }
        CloseHandle(hSnap);
    }

    if (procId == 0) {
        return 0;
    }

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32FirstW(hSnap, &modEntry)) {
            do {
                if (!_wcsicmp(modEntry.szModule, moduleName)) {
                    modBaseAddr = (Address)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &modEntry));
        }
        CloseHandle(hSnap);
    }

    return modBaseAddr;
}

HANDLE GetProcessHandle(const wchar_t* processName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32FirstW(hSnap, &procEntry)) {
            do {
                if (!_wcsicmp(procEntry.szExeFile, processName)) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &procEntry));
        }
        CloseHandle(hSnap);
    }

    if (procId == 0) {
        return nullptr;
    }

    return OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, procId);
}

template<typename T>
T ReadMemory(HANDLE hProcess, Address address) {
    T value = T();
    ReadProcessMemory(
        hProcess,
        (LPCVOID)address,
        &value,
        sizeof(T),
        NULL
    );
    return value;
}

template<typename T>
void WriteMemory(HANDLE hProcess, Address address, const T& value) {

    WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(T), NULL);
}


const Address client_base = GetModuleBaseAddress(targetProcess, L"client.dll");
const Address engine_base = GetModuleBaseAddress(targetProcess, L"engine.dll");

const Address PLAYER_POINTER_OFFSET = 0x6098C8;
const Address ENTITY_LIST_OFFSET = 0x6098E8;
const Address HEALTH_OFFSET = 0xD0;
const Address PITCH_BASE = 0x53E4E4;
const Address YAW_BASE = 0x53E4E8;


int main() {

    if (client_base == 0) {
        std::wcerr << L"client.dll not found" << std::endl;
        std::cin.get();
        return 1;
    }

    HANDLE hProcess = GetProcessHandle(targetProcess);

    if (hProcess == nullptr) {
        std::wcerr << L"Erro" << std::endl;
        std::cin.get();
        return 1;
    }

    Address playerPointerAddress = client_base + PLAYER_POINTER_OFFSET;

    Address localPlayerBase = ReadMemory<Address>(hProcess, playerPointerAddress);

    if (localPlayerBase == 0) {
        std::wcerr << L"Erro: Dynamic address not found" << std::endl;
        CloseHandle(hProcess);
        std::cin.get();
        return 1;
    }

    Address healthAddress = localPlayerBase + HEALTH_OFFSET;

    const int hp = 999;

    while (true) {

        Address localPlayerBase = ReadMemory<Address>(hProcess, playerPointerAddress);

        if (localPlayerBase != 0) {
            Address healthAddress = localPlayerBase + HEALTH_OFFSET;

            int currentHealth = ReadMemory<int>(hProcess, healthAddress);

            WriteMemory<int>(hProcess, healthAddress, hp);

        }
        else {
            std::cout << "Awaiting player address" << std::endl;
        }
    }
    Sleep(100);


    std::wcout << L"client.dll Base: 0x" << std::hex << client_base << std::endl;
    std::wcout << L"engine.dll Base: 0x" << std::hex << engine_base << std::endl;

    std::cout << "Player Pointer static address: 0x" << std::hex << playerPointerAddress << std::endl;
    std::cout << "Local Player Base dynamic address: 0x" << std::hex << localPlayerBase << std::endl;
    std::cout << "Health address: 0x" << std::hex << healthAddress << std::endl;
    std::cout << "New health: " << std::dec << hp << std::endl;

    CloseHandle(hProcess);

    std::cin.get();

    return 0;
}