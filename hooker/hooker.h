#pragma once

#ifdef EXPORTING_DLL
extern "C" __declspec(dllexport) void myFunc(PTSTR szSubkey);
//#else
//extern __declspec(dllimport) void myFunc(PTSTR szSubkey);
#endif
