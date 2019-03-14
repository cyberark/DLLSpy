#include "Impersonation.h"

ESTATUS FindProcessId(const TCHAR *processName, DWORD *pProcessId)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	ESTATUS eReturn = ESTATUS_INVALID;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		eReturn = ESTATUS_ENUMERATION_ERROR;
		goto lblCleanup;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT
							  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		//Could find process
		eReturn = ESTATUS_ENUMERATION_ERROR;
		goto lblCleanup;
	}

	do
	{
		if (0 == strcmp(processName, pe32.szExeFile))
		{
			*pProcessId = pe32.th32ProcessID;
			eReturn = ESTATUS_SUCCESS;
			goto lblCleanup;
		}
	} while (Process32Next(hProcessSnap, &pe32));

lblCleanup:
	if (INVALID_HANDLE_VALUE == hProcessSnap)
		CloseHandle(hProcessSnap);

	return eReturn;
}

ESTATUS GetImpersonatedToken(PHANDLE hImpersonatedToken, const TCHAR *sProcessName)
{
	HANDLE hToken = NULL;
	DWORD dwPid = 0;
	ESTATUS eReturn;
	HANDLE hProcess = NULL;
	BOOL bOpenProcessToken = FALSE;

	eReturn = FindProcessId(sProcessName, &dwPid);
	if (dwPid == 0 || ESTATUS_FAILED(eReturn))
	{ 
		goto lblCleanup;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);
	bOpenProcessToken = OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken);

	if (!bOpenProcessToken)
	{
		eReturn = ESTATUS_DUPLICATE_TOKEN_ERROR;
		goto lblCleanup;
	}

	DuplicateToken(hToken, SecurityImpersonation, hImpersonatedToken);
	eReturn = ESTATUS_SUCCESS;

lblCleanup:

	if (hProcess != NULL)
		CloseHandle(hProcess);
	if(hToken != NULL)
		CloseHandle(hToken);

	return eReturn;
}

ESTATUS CanAccessDirectory(LPCTSTR folderName, DWORD genericAccessRights, PHANDLE hImpersonatedToken, PBOOL hHasAccess)
{
	DWORD dwLength = 0;
	bool bHasAccess = false;
	ESTATUS eRetrun = ESTATUS_INVALID;

	if (!GetFileSecurity(folderName, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, &dwLength) && ERROR_INSUFFICIENT_BUFFER == ::GetLastError())
	{
		PSECURITY_DESCRIPTOR security = static_cast< PSECURITY_DESCRIPTOR >(::malloc(dwLength));
		if (security && GetFileSecurity(folderName, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, security, dwLength, &dwLength))
		{
			GENERIC_MAPPING mapping = { 0xFFFFFFFF };
			PRIVILEGE_SET privileges = { 0 };
			DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
			BOOL result = FALSE;

			mapping.GenericRead = FILE_GENERIC_READ;
			mapping.GenericWrite = FILE_GENERIC_WRITE;
			mapping.GenericExecute = FILE_GENERIC_EXECUTE;
			mapping.GenericAll = FILE_ALL_ACCESS;

			MapGenericMask(&genericAccessRights, &mapping);
			eRetrun = ESTATUS_SUCCESS;
			if (AccessCheck(security, *hImpersonatedToken, genericAccessRights, &mapping, &privileges, &privilegesLength, &grantedAccess, &result))
			{
				*hHasAccess = (result == TRUE);
			}

			free(security);
		}
		eRetrun = ESTATUS_GET_FILE_SECURIT_ERROR;
	}

	return eRetrun;
}

ESTATUS GetLogonFromToken(HANDLE hToken, string& strUser, string& strdomain)
{
	DWORD dwSize = MAX_PATH;
	ESTATUS eReturn = ESTATUS_INVALID;
	DWORD dwLength = 0;
	PTOKEN_USER ptu = NULL;
	SID_NAME_USE SidType;



	if (GetTokenInformation(hToken, TokenUser, (LPVOID)ptu, 0, &dwLength))
		goto Cleanup;

	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		goto Cleanup;

	ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);

	if (!GetTokenInformation(hToken, TokenUser, (LPVOID)ptu, dwLength, &dwLength ))
		goto Cleanup;
	
	if (!LookupAccountSid(NULL, ptu->User.Sid, (char*)&strUser[0], &dwSize, (char*)&strdomain[0], &dwSize, &SidType))
	{
		eReturn = ESTATUS_DUPLICATE_TOKEN_ERROR;
		goto Cleanup;
	}


Cleanup:

	if (ptu != NULL)
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
	return eReturn;
}