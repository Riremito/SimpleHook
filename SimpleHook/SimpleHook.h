#ifndef __SIMPLEHOOK_H__
#define __SIMPLEHOOK_H__

#include<Windows.h>

#ifndef SIMPLEHOOK_EXPORT
#ifndef _WIN64
#pragma comment(lib, "../Share/SimpleHook.lib")
#else
#pragma comment(lib, "../Share/SimpleHook64.lib")
#endif
#define SIMPLEHOOK_IMPORT __declspec(dllimport)
#else
#define SIMPLEHOOK_IMPORT
#endif

namespace SimpleHook {
	bool SIMPLEHOOK_IMPORT Hook(void *HookFunction, void *FunctionPointer, ULONG_PTR Address, ULONG_PTR OverWrite = 0);
	bool SIMPLEHOOK_IMPORT UnHook();
}

// APIフック
#define SHook(api) \
{\
	if(!SimpleHook::Hook(api##_Hook, &_##api, (ULONG_PTR)##api)) {\
		MessageBoxW(NULL, L""#api, L"NG", MB_OK);\
	}\
}

// DLLを指定するAPIフック
#define SHookNT(dll, api) \
{\
	HMODULE hModule = GetModuleHandleW(L""#dll);\
	if (hModule) {\
		ULONG_PTR uAddress = (ULONG_PTR)GetProcAddress(hModule, ""#api);\
		if (uAddress) {\
			if(!SimpleHook::Hook(api##_Hook, &_##api, uAddress)) {\
				MessageBoxW(NULL, L""#api, L"NG", MB_OK);\
			}\
		}\
	}\
}

// アドレスを指定するフック
#define SHookFunction(name, address) \
{\
	if(!SimpleHook::Hook(name##_Hook, &_##name, address)) {\
		MessageBoxW(NULL, L""#name, L"NG", MB_OK);\
	}\
}

#endif