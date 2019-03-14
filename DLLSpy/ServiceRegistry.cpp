#include "ServiceRegistry.h"
#include "Utils.h"



ESTATUS EnumerateServicesFromRegistry(PProcessContainer p)
{
	LSTATUS lResult = 0;
	HKEY hKey;
	ESTATUS eReturn = ESTATUS_INVALID;
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", 0, KEY_ENUMERATE_SUB_KEYS | KEY_READ | KEY_QUERY_VALUE, &hKey);
	if (lResult == ERROR_SUCCESS)
	{
		TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
		DWORD    cbName;                   // size of name string 
		TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
		DWORD    cchClassName = MAX_PATH;  // size of class string 
		DWORD    cSubKeys = 0;               // number of subkeys 
		DWORD    cbMaxSubKey;              // longest subkey size 
		DWORD    cchMaxClass;              // longest class string 
		DWORD    cValues;              // number of values for key 
		DWORD    cchMaxValue;          // longest value name 
		DWORD    cbMaxValueData;       // longest value data 
		DWORD    cbSecurityDescriptor; // size of security descriptor 
		FILETIME ftLastWriteTime;      // last write time 
		DWORD i, retCode;

		// Get the class name and the value count. 
		retCode = RegQueryInfoKey(hKey, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues, &cchMaxValue, &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime);

		if (cSubKeys)
		{
			for (i = 0; i < cSubKeys; i++)
			{
				cbName = MAX_KEY_LENGTH;
				retCode = RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime);
				if (retCode == ERROR_SUCCESS)
				{
					TCHAR cKeyName[MAX_PATH] = "SYSTEM\\CurrentControlSet\\Services\\";
					strncat_s(cKeyName, MAX_PATH, achKey, strlen(achKey));
					string ServicePath = "";
					ESTATUS dwResult = GetServiceBinary(cKeyName, ServicePath);
					if (ServicePath != "" && dwResult == ESTATUS_SUCCESS)
					{
						if(p->vsProcessBinary.find(ServicePath) == p->vsProcessBinary.end())
							p->vsProcessBinary.insert(ServicePath);
					}
				}
			}
		}
		RegCloseKey(hKey);
	}
	if (p->vsProcessBinary.size() > 0)
		eReturn = ESTATUS_SUCCESS;

	return eReturn;
}

ESTATUS GetServicePathFromRegistryDllKey(const TCHAR *cKeyName, string &ServicePath)
{
	ESTATUS eReturn = ESTATUS_INVALID;
	DWORD dwType = REG_EXPAND_SZ;
	DWORD dwSize = FULL_PATH_SIZE;
	HKEY hServiceDLLKey = NULL;
	TCHAR cDLLName[FULL_PATH_SIZE] = { 0 };
	TCHAR cDLLKey[FULL_PATH_SIZE] = { 0 };
	strncpy_s(cDLLKey, FULL_PATH_SIZE, cKeyName, strlen(cKeyName));
	strncat_s(cDLLKey, FULL_PATH_SIZE, "\\Parameters", strlen("\\Parameters"));

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, cDLLKey, 0, KEY_ENUMERATE_SUB_KEYS | KEY_READ | KEY_QUERY_VALUE, &hServiceDLLKey) == ERROR_SUCCESS)
	{
		RegQueryValueExA(hServiceDLLKey, "ServiceDll", NULL, &dwType, (LPBYTE)&cDLLName, &dwSize);
		if (cDLLName[0] != '\0')
		{
			ServicePath = ExpandPath(string(cDLLName));
			RegCloseKey(hServiceDLLKey);
			eReturn = ESTATUS_SUCCESS;
		}
		else
			eReturn = ESTATUS_REG_OPEN_KEY_ERROR;		
	}
	return eReturn;
}

ESTATUS GetServiceBinary(const TCHAR *cKeyName, string &ServicePath)
{
	HKEY hNewKey = NULL;
	DWORD dwSize = REG_DWORD;
	DWORD dwType = REG_SZ;
	DWORD dwServiceType = 0;
	TCHAR cServiceImagePath[FULL_PATH_SIZE] = { 0 };
	DWORD dwStartMode = 0;
	ESTATUS eReturn = ESTATUS_INVALID;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, cKeyName, 0, KEY_ENUMERATE_SUB_KEYS | KEY_READ | KEY_QUERY_VALUE, &hNewKey) == ERROR_SUCCESS)
	{
		RegQueryValueExA(hNewKey, "Start", NULL, &dwType, (LPBYTE)&dwStartMode, &dwSize);
		dwSize = REG_DWORD;
		RegQueryValueExA(hNewKey, "Type", NULL, &dwType, (LPBYTE)&dwServiceType, &dwSize);
		dwType = REG_SZ;
		dwSize = FULL_PATH_SIZE;
		RegQueryValueExA(hNewKey, "ImagePath", NULL, &dwType, (LPBYTE)&cServiceImagePath, &dwSize);

		if ((dwServiceType == 0x20 || dwServiceType == 0x10 || dwServiceType == 0x110) && (dwStartMode != 0x4) && (cServiceImagePath[0] != '\0'))
		{
			if (strstr(cServiceImagePath, "svchost") == NULL)
			{
				TCHAR cBinaryPath[FULL_PATH_SIZE] = { 0 };
				if (strchr(cServiceImagePath, '"') != NULL)			
					GetBinaryPath(cBinaryPath, cServiceImagePath);				
				else
					strncat_s(cBinaryPath, FULL_PATH_SIZE, cServiceImagePath, strlen(cServiceImagePath));

				ServicePath = ExpandPath(string(cBinaryPath));
				eReturn = ESTATUS_SUCCESS;
			}
			else
				eReturn = GetServicePathFromRegistryDllKey(cKeyName, ServicePath);	
		}
	}

	if (hNewKey != NULL)
		RegCloseKey(hNewKey);
	
	return eReturn;
}
