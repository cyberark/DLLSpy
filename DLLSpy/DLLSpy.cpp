#include "DLLSpy.h"
#include "Impersonation.h"
#include "Utils.h"
#include "ServiceRegistry.h"
#include "general.h"
#include "StringsExtractor.h"


ofstream fLogFile;
ofstream fNewLog;
string sSystemPaths[] = { "C:\\Windows\\System32", "C:\\Windows\\System", "C:\\Windows" };

unsigned char READABLE_CHARCATERS[90] = "'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+=-`{}[]:;,.? ";

int _tmain(int argc, TCHAR *argv[])
{
	ESTATUS eReturn = ESTATUS_INVALID;
	string banner =
		R"( ______   _        _        _______  _______          
(  __  \ ( \      ( \      (  ____ \(  ____ )|\     /|
| (  \  )| (      | (      | (    \/| (    )|( \   / )
| |   ) || |      | |      | (_____ | (____)| \ (_) / 
| |   | || |      | |      (_____  )|  _____)  \   /  
| |   ) || |      | |            ) || (         ) (   
| (__/  )| (____/\| (____/\/\____) || )         | |   
(______/ (_______/(_______/\_______)|/          \_/                                                        
)";
	cout << banner << endl;

	if (!IsUserAnAdmin())
	{
		cout << "DLLSpy must be activated with elevated privileges, shutting down." << endl;	
		goto lblCleanup;
	}
	eReturn = ParseCommandLineArguments(argc, argv);
		
lblCleanup:
	if (ESTATUS_FAILED(eReturn) && eReturn != ESTATS_MISSING_ARGUMENTS)
		cout << "DLLSpy exited with error: " << eReturn << endl;
	return 0;
}


ESTATUS ParseCommandLineArguments(int argc, TCHAR *argv[])
{
	string sOutputPath = "";
	bool bDynamic = false;
	bool bStatic = false;
	bool bRecursive = false;
	DWORD dwRecursionLevel = 0;
	ESTATUS eReturn = ESTATS_MISSING_ARGUMENTS;

	if (argc > 1)
	{
		for (int i = 1; i < argc; i++)
		{
			if (!_stricmp(argv[i], "-o"))
			{
				if (argv[i + 1] != NULL)
					sOutputPath = string(argv[i + 1]);			
				else
				{
					eReturn = ESTATS_MISSING_ARGUMENTS;
					goto lblCleanup;
				}
			}
			
			else if (!_stricmp(argv[i], "-s"))
				bStatic = true;
			else if (!_stricmp(argv[i], "-d"))
				bDynamic = true;

			else if (!_stricmp(argv[i], "-r"))
			{
				if (argv[i+1] != NULL)
				{
					int command_level = *argv[i + 1];
					if (!isdigit(command_level))
						goto lblCleanup;
					bRecursive = true;
					dwRecursionLevel = command_level - 0x30;
				}
				else 
					goto lblCleanup;
			}
		}
		if (bDynamic == false)
		{
			eReturn = ESTATS_MISSING_ARGUMENTS;
			goto lblCleanup;
		}
		if (!sOutputPath.compare(""))
			AssembleCSVPath(sOutputPath);

		eReturn = FindDllHjacking(sOutputPath, bStatic, bRecursive, dwRecursionLevel);
	}


lblCleanup:
	if (eReturn == ESTATS_MISSING_ARGUMENTS)
	{
		cout << "Usage: DLLSPY.exe" << endl;
		cout << "-d [mandatory] Find DLL hijacking in all running processes and services." << endl;
		cout << "-s [optional] Search for DLL references in the binary files of current running processes and services." << endl;
		cout << "-r n [optional] Recursion search for DLL references in found DLL files privous scan." << endl << "   n is the number is the level of the recursion" << endl;
		cout << "-o [optional] Output path for the results in csv format of" << endl;
		cout << "               By ommiting this option, a defulat result file would be created on the desktop of the current user." << endl;
		cout << "               Named after the name of the computer .csv" << endl;
		
	}
	return eReturn;
}


ESTATUS AssembleCSVPath(string &OutputPath)
{
	TCHAR cDesktopPath[MAX_PATH] = { 0 };
	TCHAR cComputerName[MAX_PATH] = { 0 };
	string Extenstion = ".csv";
	DWORD dwSize = MAX_PATH;
	BOOL bSuccess = false;
	ESTATUS eReturn = ESTATUS_INVALID;

	GetComputerNameA(cComputerName, &dwSize);
	bSuccess = SHGetSpecialFolderPath(HWND_DESKTOP, cDesktopPath, CSIDL_DESKTOP, FALSE);
	if (!bSuccess)
	{
		cout << "Could not find home directory" << endl;
		goto lblCleanup;

	}
	OutputPath = string(cDesktopPath) + "\\" + string(cComputerName) + Extenstion;
	eReturn = ESTATUS_SUCCESS;

lblCleanup:
	return eReturn;
}

ESTATUS FindDllHjacking(string OutputPath, bool bStatic, bool bRecrusive, DWORD level)
{

	ESTATUS eReturn = ESTATUS_INVALID;
	ProcessContainer p = ProcessContainer();  
	fLogFile.open("DLLSpy.log");

	cout << "Start analyzing processes dynamicly" << endl;
	

	fLogFile << "Dynamic Extraction" << endl;
	fLogFile << "Severity," << "Exist,"<< "Binary," << "DLL" << endl;
	eReturn = EnumerateRunningProcesses(&p);
	fLogFile << endl;
	cout << "Done looking for dynamic processes hijacking" << endl;
	cout << "======================================================================================" << endl;
	
	if (bStatic)
	{
		cout << "Start analyzing processes executables, static analysis" << endl;
		fLogFile << "Static Extraction" << endl;
		fLogFile << "Severity," << "Exist," << "Binary," << "DLL" << endl; 

		eReturn = EnumerateProcessesBinaries(&p);
		fLogFile << endl;
		cout << "Done looking for static executables hijacking" << endl;
		cout << "=================================================================================" << endl;
	}

	if (bRecrusive && level  < 5)
	{
		cout << "Start Recursive search" << endl;
		fLogFile << "Recursive Extraction" << endl;
		fLogFile << "Severity," << "Exist," << "Binary," << "DLL" << endl;

		eReturn = RecursieveEnumeration(&p, level);
		fLogFile << endl;
		cout << "Done looking for Recursive Extraction" << endl;
		cout << "=================================================================================" << endl;
	}

	cout << "Results are in: " << OutputPath << endl;
	fLogFile.close();

	print(&p, OutputPath);
	return eReturn;
}

ESTATUS EnumerateRunningProcesses(PProcessContainer p)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry;
	MODULEENTRY32 moduleEntry;
	HANDLE hImpersonatedToken = NULL;
	TCHAR * processName = "explorer.exe";
	ESTATUS eReturn = ESTATUS_INVALID;
	string sUserName;
	string sDomainName;

	//Impersonate explorer.exe token in order to preform access check with week privileges
	eReturn = GetImpersonatedToken(&hImpersonatedToken, processName);
	if (hImpersonatedToken == NULL || ESTATUS_FAILED(eReturn))
	{
		goto lblCleanup;
	}
	eReturn = GetLogonFromToken(hImpersonatedToken, sUserName, sDomainName);

	processEntry.dwSize = sizeof(PROCESSENTRY32);
	// System Process
	Process32First(hSnapshot, &processEntry);

	while (Process32Next(hSnapshot, &processEntry))
	{
		HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processEntry.th32ProcessID);
		moduleEntry.dwSize = sizeof(MODULEENTRY32);
		Module32First(moduleSnapshot, &moduleEntry);
		if (moduleSnapshot == INVALID_HANDLE_VALUE)
		{
			continue;
		}

		string sProcessName = processEntry.szExeFile;
		string sProcessDir = GetDirPath(sProcessName);
		string sProcessPath = moduleEntry.szExePath;
		p->vsProcessBinary.insert(sProcessPath);

		ProcessData pData = ProcessData(sProcessPath.c_str(), sUserName.c_str(), sDomainName.c_str());


		while (Module32Next(moduleSnapshot, &moduleEntry))
		{
			eReturn = ESTATUS_SUCCESS;
			moduleEntry.dwSize = sizeof(MODULEENTRY32);

			string sModuleName = string(moduleEntry.szExePath);

			string sExeDirPath = GetDirPath(sModuleName);
			bool isSecureDir = false;
			//string sSystemPaths[] = { "C:\\Windows\\System32", "C:\\Windows\\System", "C:\\Windows" };

			for (int i = 0; i < sizeof(sSystemPaths) / sizeof(sSystemPaths[0]); ++i)
			{
				if (CompareStrings(sExeDirPath, sSystemPaths[i]))
				{
					isSecureDir = true;
					break;
				}
			}
			if (!isSecureDir)
			{
				// Check if current logged on user is able has write permission to directory, if so we can hijack a dll there
				BOOL bDirAccessAllowd = FALSE;
				BOOL bFileAllwod = FALSE;

				CanAccessDirectory(sExeDirPath.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bDirAccessAllowd);
				CanAccessDirectory(sModuleName.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bFileAllwod);

				if (bDirAccessAllowd && bFileAllwod)
				{
					DLLData dData = DLLData(sModuleName, "High", "Low", true);
					pData.vsDLLs.insert(dData);
					if (DEBUG_PRINT)
					{
						cout << "High Severity in process: " << sProcessName.c_str() << "\tDLL: " << sModuleName.c_str() << endl;
						fLogFile << sUserName.c_str() << "," << "High," << "Yes, " << sProcessName.c_str() << "," << sModuleName.c_str() << endl;
					}
				}
			}
		}
		if (!pData.vsDLLs.empty())
		{

			auto it = BinaryExists(p, pData.sBinaryPath);
			if (it != p->vProcessData.end())
				it->vsDLLs.insert(pData.vsDLLs.begin(), pData.vsDLLs.end());
			else
				p->vProcessData.push_back(pData);
		}
	}

lblCleanup:
	if (hSnapshot != NULL)
		CloseHandle(hSnapshot);
	if (hImpersonatedToken != NULL)
		CloseHandle(hImpersonatedToken);

	return eReturn;
}


ESTATUS EnumerateProcessesBinaries(PProcessContainer p)
{
	ESTATUS eReturn = ESTATUS_INVALID;
	eReturn = EnumerateServicesFromRegistry(p);
	if (eReturn != ESTATUS_SUCCESS)
		goto lblCleanup;
	eReturn = GetServicesDLLS(p);
	if (eReturn != ESTATUS_SUCCESS)
		goto lblCleanup;
	eReturn = GetHijackedDirectories(p);

	p->sGlobalBinaries.insert(p->vsProcessBinary.begin(), p->vsProcessBinary.end());


lblCleanup:

	return eReturn;
}

ESTATUS RecursieveEnumeration(PProcessContainer p, DWORD level)
{
	ESTATUS eReturn = ESTATUS_INVALID;

	for (size_t i = 0; i < level; ++i)
	{
		RecursiveChecking(p);
		p->msvStaticProcessMap.clear();

		eReturn = GetServicesDLLS(p);
		if (eReturn != ESTATUS_SUCCESS)
			goto lblCleanup;

		eReturn = GetHijackedDirectories(p);
		p->sGlobalBinaries.insert(p->vsProcessBinary.begin(), p->vsProcessBinary.end());
	}

lblCleanup:
	return eReturn;
}


ESTATUS GetServicesDLLS(PProcessContainer p)
{
	ESTATUS eReturn = ESTATUS_INVALID;	
	StringsExtractor m;
	long lOutputSize;
	for (auto sServiceName : p->vsProcessBinary)
	{
			string sRawOutput;
			char *a = m.GenerateStrings(READABLE_CHARCATERS, (char*)sServiceName.c_str(), 6, "\n", &lOutputSize, sRawOutput);
			sRawOutput = string(&a[0], &a[lOutputSize]);
			free(a);

			string token;
			istringstream tokenStream(sRawOutput);
			while (getline(tokenStream, token, '\n'))
			{

				//Double filtring, make sure we don't have any wierd chracters
				GetDllFromToken(token);
				GetDllFromToken(token);

				if (token.compare(""))
					if (find(p->msvStaticProcessMap[sServiceName].begin(), p->msvStaticProcessMap[sServiceName].end(), token) == p->msvStaticProcessMap[sServiceName].end())
					{
						p->msvStaticProcessMap[sServiceName].push_back(token);
					}
			}
		}
		eReturn = ESTATUS_SUCCESS;
		return eReturn;
}



ESTATUS GetHijackedDirectories(PProcessContainer p)
{
	HANDLE hImpersonatedToken = NULL;
	TCHAR *sProcessName = "explorer.exe";
	ESTATUS eReturn = ESTATUS_INVALID;
	//string sSystemPaths[] = { "C:\\Windows\\System32", "C:\\Windows\\System", "C:\\Windows" };
	string sUserName;
	string sDomainName;

	eReturn = GetImpersonatedToken(&hImpersonatedToken, sProcessName);
	if (ESTATUS_FAILED(eReturn))
		goto lblCleanup;
	eReturn = GetLogonFromToken(hImpersonatedToken, sUserName, sDomainName);


	eReturn = ESTATUS_SUCCESS;
	for (auto &map_iter : p->msvStaticProcessMap)
	{
		BOOL bExist = FALSE;
		string ProcessPath = map_iter.first;
		string sProcessDir = GetDirPath(ProcessPath) + "\\";
		ProcessData pData = ProcessData(map_iter.first, sUserName.c_str(), sDomainName.c_str());

		for (auto vec_iter = map_iter.second.cbegin(); vec_iter != map_iter.second.cend(); ++vec_iter)
		{
			BOOL isSecureDir = FALSE;
			string sDllName = *vec_iter;
			string sOptionalDllPath = sProcessDir + sDllName;
			DLLData dData = DLLData();
			BOOL bDirAccessAllowd = FALSE;
			BOOL bFileAllwod = FALSE;
			
			// If the DLL is in full path foramt, there is no chance for hijacking even if the DLL exist
			if (PathFileExistsA(sDllName.c_str()))
				break;

			if (PathFileExistsA(sOptionalDllPath.c_str()))
			{
				bExist = TRUE;

				CanAccessDirectory(sProcessDir.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bDirAccessAllowd);
				CanAccessDirectory(sOptionalDllPath.c_str(), GENERIC_WRITE, &hImpersonatedToken, &bFileAllwod);

				if(!bDirAccessAllowd || !bFileAllwod)
					isSecureDir = TRUE;
			}
			else
			{
				for (int i = 0; i < sizeof(sSystemPaths) / sizeof(sSystemPaths[0]); ++i)
				{
					string sSystemDll = sSystemPaths[i] + "\\" + sDllName;
					if (PathFileExistsA(sSystemDll.c_str()))
					{
						isSecureDir = TRUE;
						break;
					}
				}
			}

			if (!isSecureDir)
			{
				if (dData.bExist)
					dData.sServirity = "high";
				else if (ends_with(pData.sBinaryPath, "dll"))
					dData.sServirity = "Medium";
				else
					dData.sServirity = "Low";

				dData.bExist = bExist == TRUE ? true : false;
				dData.sBinaryPath = sDllName;
				dData.sPermissionLevel = "Low";				
				pData.vsDLLs.insert(dData);

				if (DEBUG_PRINT)
				{
					if (bExist)
					{
						fLogFile << sUserName.c_str() << "," << "High, " << "Yes," << ProcessPath.c_str() << "," << sDllName << endl;
					}
					else if (!isSecureDir)
					{
						fLogFile << sUserName.c_str() << "," << "Low, " << "No," << ProcessPath.c_str() << "," << sDllName << endl;
					}
				}
			}
		}

		if (!pData.vsDLLs.empty())
		{
			auto it = BinaryExists(p, pData.sBinaryPath);
			if (it != p->vProcessData.end())		
				it->vsDLLs.insert(pData.vsDLLs.begin(), pData.vsDLLs.end());
			else
				p->vProcessData.push_back(pData);			
		}
	}
lblCleanup:
	if (hImpersonatedToken != NULL)
		CloseHandle(hImpersonatedToken);

	return eReturn;

}

void RecursiveChecking(PProcessContainer p)
{
	ESTATUS eReturn = ESTATUS_INVALID;
	//string sSystemPaths[] = { "C:\\Windows\\System32", "C:\\Windows\\System", "C:\\Windows" };

	p->vsProcessBinary.clear();

	for (auto &map_iter : p->msvStaticProcessMap)
	{
		string ProcessPath = map_iter.first;
		string sProcessDir = GetDirPath(ProcessPath) + "\\";


		for (auto vec_iter = map_iter.second.cbegin(); vec_iter != map_iter.second.cend(); ++vec_iter)
		{
			string sDllName = *vec_iter;
			string sOptionalDllPath = sProcessDir + sDllName;
			string sDefinetDLLPath = "";

			// Incase dll name contains expanded enviroment variables
			if (PathFileExistsA(sDllName.c_str()))
				sDefinetDLLPath = sDllName;
			
			else if (PathFileExistsA(sOptionalDllPath.c_str()))
				sDefinetDLLPath = sOptionalDllPath;
			else
			{
				for (int i = 0; i < sizeof(sSystemPaths) / sizeof(sSystemPaths[0]); ++i)
				{
					string sSystemDll = sSystemPaths[i] + "\\" + sDllName;
					if (PathFileExistsA(sSystemDll.c_str()))
					{
						sDefinetDLLPath = sSystemDll;
						break;
					}
				}
			}
			if (sDefinetDLLPath.compare("") && p->sGlobalBinaries.find(sDefinetDLLPath) == p->sGlobalBinaries.end())
				p->vsProcessBinary.insert(sDefinetDLLPath);
		}
	}

	return;
}

vector<ProcessData>::iterator BinaryExists(PProcessContainer p, string sBinaryPath)
{
	for (auto it = p->vProcessData.begin(); it != p->vProcessData.end(); ++it)
	{
		if (!(*it).sBinaryPath.compare(sBinaryPath))
			return it;
	}
	
	return p->vProcessData.end();
}


void print(PProcessContainer p, string sOutputPath)
{

	fNewLog.open(sOutputPath.c_str(), std::ofstream::out | std::ofstream::app);

	Beautify(p, "Critical endangered applications", "High");
	Beautify(p, "Medium endangered applications", "Medium");
	Beautify(p, "Least endangered applications", "Low");

	fNewLog.close();


	return;
}

string GetFilename(string sFullPath)
{
	auto index = sFullPath.rfind("\\");
	if (index != string::npos)
		sFullPath = sFullPath.substr(index+1, sFullPath.length());
	return sFullPath;
}

void Beautify(PProcessContainer p, string message, string sevirity)
{
	fNewLog << message << endl << endl;
	for (auto &it : p->vProcessData)
	{
		int count = 0;
		for (auto j : it.vsDLLs)
		{
			if (!j.sServirity.compare(sevirity))
			{
				count++;
				if (count == 1)
				{
					string sFileName = GetFilename(it.sBinaryPath);
					fNewLog << "Application:  " << sFileName << "," << "Path:  " << it.sBinaryPath.c_str() << "," << "User:  " << it.sUserName << "," << "Sevirtiy:  " << sevirity << endl;
					fNewLog << "Modules" << endl;
				}
				fNewLog << j.sBinaryPath.c_str() << endl;
			}
		}
		if(count)
			fNewLog << endl;
	}

}
