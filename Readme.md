# DLLSpy

DLLSpy is a tool that detects DLL hijacking in running processes, services and in their binaries.

## Installation

The easiest way to get DLLSpy from git is by running the following command:

```
git clone https://github.com/cyberark/DLLSpy
```
## Usage
DLLSpy must be activated with admin rights because it enumerates all processes and services from all users. Execution the program without administrative rights will show the banner and help manual. The default output file is user desktop\machinename.csv
```
C:\Users\john\Desktop\DLLSpy.exe
 ______   _        _        _______  _______
(  __  \ ( \      ( \      (  ____ \(  ____ )|\     /|
| (  \  )| (      | (      | (    \/| (    )|( \   / )
| |   ) || |      | |      | (_____ | (____)| \ (_) /
| |   | || |      | |      (_____  )|  _____)  \   /
| |   ) || |      | |            ) || (         ) (
| (__/  )| (____/\| (____/\/\____) || )         | |
(______/ (_______/(_______/\_______)|/          \_/

Usage: DLLSpy.exe
-d [mandatory] Find DLL hijacking in all running processes and services.
-s [optional] Search for DLL references in the binary files of current running processes and services.
-r n [optional] Recursion search for DLL references in found DLL files privous scan.
   n is the number is the level of the recursion
-o [optional] Output path for the results in csv format of
               By ommiting this option, a defulat result file would be created on the desktop of the current user.
               Named after the name of the computer .csv
```
## Execution Flags
```
-d: Mandatory, Scan loaded modules.
-o: Specify an output file. 
-s: Static scan, find missing DLLs and DLLs in binaries
-r <number>:  Recursive scan, ‘number’ is the depth of the recursion. 
```
## Overview of DLLSpy

DLLSpy has three engines under its belt.

Dynamic – First, scan the loaded modules by iterating the process loaded module list. Then checks if any of those modules could be hijacked by trying to write to their file location on disk and by checking if they could be overwritten. This is done after duplicating the access token of explorer.exe, which is a weak token. We do that in order to test whether we have write permission to the DLL location and the DLL itself as a regular user.

Static – Locate all strings that contain a DLL name or DLL Path in the binary files of running processes.

Recursive – Statically scan all the DLLs of the processes previously examined. The goal is to find more DLLs that are loaded by those DLLs and see if they are vulnerable to hijacking


## Supported Architecture
DLLSpy was successfully tested on Windows 7+ operating systems. 

## Contributing
DLLSpy runs on Windows 7 + at the moment. We highly encourage you to contribute in the way of creating new modules or improving the existing ones.



## License
[GPL](https://www.gnu.org/licenses/gpl-3.0.en.html)
