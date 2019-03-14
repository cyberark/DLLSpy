#include "general.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

using namespace std;

ESTATUS FindProcessId(const TCHAR *processName, DWORD *pProcessId);
ESTATUS GetImpersonatedToken(PHANDLE hImpersonatedToken, const TCHAR *processName);
ESTATUS CanAccessDirectory(LPCTSTR folderName, DWORD genericAccessRights, PHANDLE hImpersonatedToken, PBOOL hHasAccess);
ESTATUS GetLogonFromToken(HANDLE hToken, string& strUser, string& strdomain);