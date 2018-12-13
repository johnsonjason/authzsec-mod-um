#include "stdafx.h"
#include <iostream>

void initialize_authzsec()
{
	std::ios_base::sync_with_stdio(false);
}

void initialize_km_sec(void* communication)
{
	
}

void attach_windows_shell()
{

}

void isolate_um_process()
{
	
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

