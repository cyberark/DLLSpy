#pragma once
#include <windows.h>
#include <string>
#include <set>
#include "DLLSpy.h"
#include "general.h"


#define MAX_KEY_LENGTH 255

using namespace std;

ESTATUS EnumerateServicesFromRegistry(PProcessContainer p);
ESTATUS GetServicePathFromRegistryDllKey(const TCHAR *cKeyName, string &ServicePath);
ESTATUS GetServiceBinary(const TCHAR *cKeyName, string &ServicePath);