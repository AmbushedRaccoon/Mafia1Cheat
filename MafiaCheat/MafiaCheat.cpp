#include <windows.h>
#include <TlHelp32.h>


#include <iostream>
#include <string>
#include <vector>
#include <thread>

#ifdef UNICODE
std::wstring exeFileName = L"Game.exe";
std::wstring moduleName = L"Game.exe";
#else // UNICODE
std::string exeFileName = "Game.exe";
std::string moduleName = "Game.exe";
#endif

std::uint32_t findProcess()
{
    HANDLE processSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnap == NULL)
    {
        return 0;
    }
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(processSnap, &pe) == FALSE)
    {
        CloseHandle(processSnap);
        return 0;
    }
    do
    {
        if (pe.szExeFile == exeFileName)
        {
            std::cout << pe.th32ProcessID << std::endl;
            CloseHandle(processSnap);
            return pe.th32ProcessID;
        }
    } while (Process32Next(processSnap, &pe));
    CloseHandle(processSnap);
    return 0;
}

std::uint32_t findModuleBaseAddress(std::uint32_t pid,
#ifdef UNICODE
    std::wstring moduleName
#else // UNICODE
    std::string moduleName
#endif
    )
{
    HANDLE moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (moduleSnap == NULL)
    {
        return 0;
    }
    MODULEENTRY32 me{ sizeof(me) };
    if (Module32First(moduleSnap, &me) == FALSE)
    {
        CloseHandle(moduleSnap);
        return 0;
    }
    do
    {
        if (me.szModule == moduleName)
        {
            std::cout << reinterpret_cast<std::uint32_t>(me.modBaseAddr) << std::endl;
            CloseHandle(moduleSnap);
            return reinterpret_cast<std::uint32_t>(me.modBaseAddr);
        }
    } while (Module32Next(moduleSnap, &me));

    CloseHandle(moduleSnap);
    return 0;
}

std::uint32_t findAddress(HANDLE processHandle, std::uint32_t moduleBaseAddress, const std::vector<std::uint32_t>& offsets)
{
    std::uint32_t prevAddress = moduleBaseAddress;
    for (int i = 0; i < offsets.size(); i++)
    {
        auto offset = offsets[i];
        prevAddress += offset;
        if (offsets.size() - i == 1)
        {
            break;
        }
        std::uint32_t readBuffer = 0;
        SIZE_T bytesReadCount = 0;
        if (ReadProcessMemory(processHandle, reinterpret_cast<void*>(prevAddress), &readBuffer, sizeof(readBuffer), NULL) == FALSE)
        {
            return 0;
        }
        prevAddress = readBuffer;
    }
    return prevAddress;
}

int main()
{
    std::uint32_t pid = findProcess();
    if (pid == 0)
    {
        return 1;
    }
    HANDLE mafiaHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (mafiaHandle == NULL)
    {
        return 2;
    }
    std::uint32_t baseAddress = findModuleBaseAddress(pid, moduleName);
    if (baseAddress == 0)
    {
        return 3;
    }
    std::vector<std::uint32_t> offsets
    {
        0x00246D4C,
        0xE4,
        0x644,
    };
    
    
    float health = 10000;
    int bullets = 1000;
    while (true)
    {
        std::uint32_t healthPointer = findAddress(mafiaHandle, baseAddress,
            {
                0x00246D4C,
                0xE4,
                0x644,
            });
        std::uint32_t bulletsPointer = findAddress(mafiaHandle, baseAddress,
            {
                0x00246D4C,
                0xE4,
                0x4A4,
            });

        if (healthPointer == 0 || bulletsPointer == 0)
        {
            return 4;
        }

        SIZE_T numberOfBytesWritten;
        WriteProcessMemory(mafiaHandle, reinterpret_cast<void*>(healthPointer), &health, sizeof(health), &numberOfBytesWritten);

        WriteProcessMemory(mafiaHandle, reinterpret_cast<void*>(bulletsPointer), &bullets, sizeof(bullets), &numberOfBytesWritten);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}