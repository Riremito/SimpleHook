#include"SimpleHook.h"
#define ZYCORE_STATIC_DEFINE
#define ZYDIS_STATIC_DEFINE
#include<inttypes.h>
#include<Zydis/Zydis.h>
#ifndef _WIN64
#pragma comment(lib, "../Lib/Zydis.lib")
#pragma comment(lib, "../Lib/Zycore.lib")
#else
#pragma comment(lib, "../Lib/Zydis64.lib")
#pragma comment(lib, "../Lib/Zycore64.lib")
#endif
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
	ULONG_PTR MemorySize;
	ULONG_PTR HookAddress;
	bool bHooked;
#ifndef _WIN64
#define JMP_OPCODE_SIZE_SHORT 2
#define JMP_OPCODE_SIZE_LONG 5
#define HOT_PATCH_SIZE 5
#else
//#define JMP_OPCODE_SIZE 14
#define JMP_OPCODE_SIZE_SHORT 6
#define JMP_OPCODE_SIZE_LONG 14
#define HOT_PATCH_SIZE 8
#endif

	void operator=(const FunctionHook&) {}
	FunctionHook(const FunctionHook&) {}

	static void Redirection(ULONG_PTR &dwEIP) {
#ifndef _WIN64
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
#endif
	}

	static bool DecodeInit() {
#ifndef _WIN64
		ZydisDecoderInit(&::zDecoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#else
		ZydisDecoderInit(&::zDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#endif
		ZydisFormatterInit(&zFormatter, ZYDIS_FORMATTER_STYLE_INTEL);
		return true;
	}

	static ULONG_PTR Decode(ULONG_PTR uStartAddress) {
		return Decode(uStartAddress, false);
	}

	static ULONG_PTR Decode(ULONG_PTR uStartAddress, bool bHotPatch) {
		static bool bDecode = false;

		if (!bDecode) {
			bDecode = DecodeInit();
		}

		ZydisDecodedInstruction zInst;
		ULONG_PTR uEIP = uStartAddress;
		Redirection(uEIP);

		ULONG_PTR uLength = 0;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&::zDecoder, (void *)uEIP, 100, &zInst))) {
			if (ZYDIS_MNEMONIC_JB <= zInst.mnemonic && zInst.mnemonic <= ZYDIS_MNEMONIC_JZ) {
				return 0;
			}
			if (zInst.mnemonic == ZYDIS_MNEMONIC_CALL) {
				return 0;
			}
			uEIP += zInst.length;
			uLength += zInst.length;
			if (bHotPatch) {
				if (uLength >= JMP_OPCODE_SIZE_SHORT) {
					return uLength;
				}
			}
			else {
				if (uLength >= JMP_OPCODE_SIZE_LONG) {
					return uLength;
				}
			}
		}

		return 0;
	}

	static bool HotPatch(ULONG_PTR uHookAddress) {
#ifndef _WIN64
		ULONG_PTR uFreeSpace = *(ULONG_PTR *)(uHookAddress - 0x05);
		for (ULONG_PTR i = 0; i < 5; i++) {
			BYTE bFreeSpace = *(BYTE *)(uHookAddress - 0x05 + i);
			if (bFreeSpace != 0x90 && bFreeSpace != 0xCC) {
				return false;
			}
		}
		return true;
#else
		ULONG_PTR uFreeSpace = *(ULONG_PTR *)(uHookAddress - 0x08);

		switch (uFreeSpace) {
		case 0xCCCCCCCCCCCCCCCC:
		case 0x9090909090909090:
		case 0x0F1F840000000000:
		{
			return true;
		}
		default:
		{
			break;
		}
		}

		return false;
#endif
	}

public:
	FunctionHook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite) {
		bHooked = false;
		Memory = NULL;
		MemorySize = OverWrite;
		HookAddress = Address;
		// 関数がリダイレクトされている場合にフックするアドレスを変更する
		Redirection(HookAddress);
		bool bHotPatch = false;
		if (MemorySize == 0) {
			bHotPatch = HotPatch(HookAddress);
			MemorySize = Decode(HookAddress, bHotPatch);
		}

		if (bHotPatch) {
			if (MemorySize < JMP_OPCODE_SIZE_SHORT) {
				return;
			}
		}
		else {
			if (MemorySize < JMP_OPCODE_SIZE_LONG) {
				return;
			}
		}

		Memory = VirtualAlloc(NULL, MemorySize + JMP_OPCODE_SIZE_LONG, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!Memory) {
			return;
		}

		void *vpAddress = (void *)(HookAddress);
		SIZE_T vpSize = MemorySize;
		ULONG_PTR uJMP_CODE_SIZE = JMP_OPCODE_SIZE_LONG;

		if (bHotPatch) {
			vpAddress = (void *)(HookAddress - HOT_PATCH_SIZE);
			vpSize += HOT_PATCH_SIZE;
			uJMP_CODE_SIZE = JMP_OPCODE_SIZE_SHORT;
		}

		DWORD old;
		if (!VirtualProtect(vpAddress, vpSize, PAGE_EXECUTE_READWRITE, &old)) {
			return;
		}

		*(ULONG_PTR *)FunctionPointer = (ULONG_PTR)Memory;
		memcpy_s(Memory, MemorySize, (void *)HookAddress, MemorySize);
#ifndef _WIN64
		((BYTE *)(Memory))[MemorySize] = 0xE9;
		*(DWORD *)&((BYTE *)(Memory))[MemorySize + 1] = (HookAddress + MemorySize) - (ULONG_PTR)&((BYTE *)(Memory))[MemorySize] - 0x05;

		if (bHotPatch) {
			*(BYTE *)(HookAddress - 0x05) = 0xE9;
			*(DWORD *)(HookAddress - 0x05 + 0x01) = (ULONG_PTR)HookFunction - (HookAddress - 0x05) - 0x05;
			*(WORD *)HookAddress = 0xF9EB;
		}
		else {
			*(BYTE *)HookAddress = 0xE9;
			*(DWORD *)(HookAddress + 0x01) = (ULONG_PTR)HookFunction - HookAddress - 0x05;
		}
#else
		*(WORD *)((ULONG_PTR)Memory + MemorySize) = 0x25FF;
		*(DWORD *)((ULONG_PTR)Memory + MemorySize + 0x02) = 0;
		*(ULONG_PTR *)((ULONG_PTR)Memory + MemorySize + 0x06) = HookAddress + MemorySize;

		if (bHotPatch) {
			*(ULONG_PTR *)(HookAddress - 0x08) = (ULONG_PTR)HookFunction;
			*(WORD *)HookAddress = 0x25FF;
			*(DWORD *)(HookAddress + 0x02) = 0xFFFFFFF2;
		}
		else {
			*(WORD *)HookAddress = 0x25FF;
			*(DWORD *)(HookAddress + 0x02) = 0;
			*(ULONG_PTR *)(HookAddress + 0x06) = (ULONG_PTR)HookFunction;
		}
#endif

		for (ULONG_PTR i = uJMP_CODE_SIZE; i < MemorySize; i++) {
			*(BYTE *)(HookAddress + i) = 0x90;
		}

		if (VirtualProtect(vpAddress, vpSize, old, &old)) {
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
	bool Hook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite) {
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