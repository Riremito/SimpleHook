#include"SimpleHook.h"
#define ZYCORE_STATIC_DEFINE
#define ZYDIS_STATIC_DEFINE
#include<inttypes.h>
#include<Zydis/Zydis.h>
#pragma comment(lib, "../Lib/Zydis.lib")
#pragma comment(lib, "../Lib/Zycore.lib")
#include<vector>

// DllMain
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
	}
	return TRUE;
}

ZydisDecoder zDecoder;
ZydisFormatter zFormatter;

// 内部的なフック処理
class FunctionHook {
private:
	void *Memory;
	DWORD MemorySize;
	ULONG_PTR HookAddress;
	bool bHooked;

	void operator=(const FunctionHook&) {}
	FunctionHook(const FunctionHook&) {}

	static void Redirection(DWORD &dwEIP) {
		if (memcmp((void *)dwEIP, "\xFF\x25", 2) == 0) {
			dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x02));
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\x55\x8B\xEC\x5D\xFF\x25", 6) == 0) {
			dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x06));
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\x8B\xFF\x55\x8B\xEC\x5D\xFF\x25", 8) == 0) {
			dwEIP = *(DWORD *)(*(DWORD *)(dwEIP + 0x08));
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\x8B\xFF\x55\x8B\xEC\x5D\xE9", 7) == 0) {
			dwEIP = (dwEIP + 0x06) + *(signed long int *)(dwEIP + 0x07) + 0x05;
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\xEB", 1) == 0) {
			dwEIP += *(char *)(dwEIP + 0x01) + 0x02;
			return Redirection(dwEIP);
		}
		if (memcmp((void *)dwEIP, "\xE9", 1) == 0) {
			dwEIP += *(signed long int *)(dwEIP + 0x01) + 0x05;
			return Redirection(dwEIP);
		}
	}

	static bool DecodeInit() {
		ZydisDecoderInit(&::zDecoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
		ZydisFormatterInit(&zFormatter, ZYDIS_FORMATTER_STYLE_INTEL);
		return true;
	}

	static DWORD Decode(DWORD dwStartAddress) {
		static bool bDecode = false;

		if (!bDecode) {
			bDecode = DecodeInit();
		}

		ZydisDecodedInstruction zInst;
		DWORD dwEIP = dwStartAddress;

		Redirection(dwEIP);

		DWORD dwLength = 0;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&::zDecoder, (void *)dwEIP, 100, &zInst))) {
			if (ZYDIS_MNEMONIC_JB <= zInst.mnemonic && zInst.mnemonic <= ZYDIS_MNEMONIC_JZ) {
				return 0;
			}
			if (zInst.mnemonic == ZYDIS_MNEMONIC_CALL) {
				return 0;
			}
			dwEIP += zInst.length;
			dwLength += zInst.length;

			if (dwLength >= 5) {
				return dwLength;
			}
		}

		return 0;
	}

public:
	FunctionHook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, DWORD OverWrite) {
		bHooked = false;
		Memory = NULL;
		MemorySize = OverWrite;
		HookAddress = Address;
		// 関数がリダイレクトされている場合にフックするアドレスを変更する
		Redirection(HookAddress);
		if (MemorySize == 0) {
			MemorySize = Decode(HookAddress);
		}

		if (MemorySize < 5) {
			return;
		}

		Memory = VirtualAlloc(NULL, MemorySize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!Memory) {
			return;
		}

		DWORD old;
		if (!VirtualProtect((void *)HookAddress, MemorySize, PAGE_EXECUTE_READWRITE, &old)) {
			return;
		}

		*(ULONG_PTR *)FunctionPointer = (ULONG_PTR)Memory;
		memcpy_s(Memory, MemorySize, (void *)HookAddress, MemorySize);
		((BYTE *)(Memory))[MemorySize] = 0xE9;
		*(DWORD *)&((BYTE *)(Memory))[MemorySize + 1] = (HookAddress + MemorySize) - (ULONG_PTR)&((BYTE *)(Memory))[MemorySize] - 0x05;
		*(BYTE *)HookAddress = 0xE9;
		*(DWORD *)(HookAddress + 0x01) = (ULONG_PTR)HookFunction - HookAddress - 0x05;

		for (DWORD i = 5; i < MemorySize; i++) {
			*(BYTE *)(HookAddress + i) = 0x90;
		}

		if (VirtualProtect((void *)HookAddress, MemorySize, old, &old)) {
			bHooked = true;
		}
		return;
	}

	~FunctionHook() {
		if (Memory) {
			DWORD old;
			if (VirtualProtect((void *)HookAddress, MemorySize, PAGE_EXECUTE_READWRITE, &old)) {
				memcpy_s((void *)HookAddress, MemorySize, (void *)Memory, MemorySize);
				VirtualFree(Memory, 0, MEM_RELEASE);
				Memory = NULL;
			}
		}
	}

	bool IsHooked() {
		return bHooked;
	}
};


// 外部向けフック処理
namespace SimpleHook {
	std::vector<FunctionHook*> HookList;
	bool Hook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, DWORD OverWrite) {
		HookList.push_back(new FunctionHook(HookFunction, FunctionPointer, Address, OverWrite));
		return HookList.back()->IsHooked();
	}

	bool UnHook() {
		for (size_t i = 0; i < HookList.size(); i++) {
			delete HookList[i];
		}
		HookList.clear();
		return true;
	}
}