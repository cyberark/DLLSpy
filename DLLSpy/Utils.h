#pragma once
#include "general.h"
#include <iostream> 
#include <tchar.h>
#include <algorithm>
#include <Windows.h>
#include <string>


using namespace std;

#define FULL_PATH_SIZE MAX_PATH * sizeof(TCHAR) * 2

bool CompareStrings(const string s1, const string s2);
TCHAR*  GetBinaryPath(TCHAR *cBinaryPath, const TCHAR *cPharse);
string GetDirPath(const string fullpath);
string ExpandPath(string sPath);
void GetDllFromToken(string & token);
void GetCanonicalDllName(string &token);
void TrimString(string &token);
