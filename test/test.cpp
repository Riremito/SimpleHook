#include"../Share/SimpleHook.h"

int (WINAPI *_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = NULL;
int WINAPI MessageBoxA_Hook(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	return _MessageBoxA(hWnd, "Hooked", lpCaption, uType);
}

int main() {
	SHook(MessageBoxA);
	MessageBoxA(NULL, "Hello World", "test", MB_OK);
	return 0;
}