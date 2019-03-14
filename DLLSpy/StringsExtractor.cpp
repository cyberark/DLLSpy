#include "StringsExtractor.h"


// -----------------------------------------------------------------------------------------------------
// Sample calling code:
//
// char *MyStringsResult;
// MyStrings my_strings;
// char FileName[64] = "c:\\windows\\system32\\cmd.exe";
// unsigned char CharsOfInterest[90] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+=-`{}[]:;,.? ";
// char TerminatorString[4] = "\r\n";
// long MinimumStringSize = 4;
// long OutputSize;
// DWORD MyStringsSizeActuallyWritten;
//
// MyStringsResult = my_strings.GenerateStrings(CharsOfInterest, FileName, MinimumStringSize, TerminatorString, &OutputSize);
//
// if (MyStringsResult)
// {
//	 SU->WriteBinaryFileFromMemory(L"c:\\Scoper\\MyStringsTest.txt", MyStringsResult, OutputSize, &MyStringsSizeActuallyWritten);
//	 free(MyStringsResult);
// }
// -----------------------------------------------------------------------------------------------------



// Constructor
StringsExtractor::StringsExtractor()
{
}

// Destructor
StringsExtractor::~StringsExtractor()
{
}

// ---------------------  
// ---------------------

char *StringsExtractor::GenerateStrings(unsigned char *CharsOfInterest, char *FileName, long MinimumStringSize, char *TerminatorString, long *OutputSize, string &sOutput)
{
	DWORD SizeOfBuffer;
	DWORD SizeActuallyRead;
	DWORD CharsOfInterestArray[256];
	unsigned char *InputFileBuffer;
	char *OutputBuffer;
	char *OutputBufferPos = NULL;
	long rc;
	long StartStringOffset;
	long UnicodeStartStringOffset;
	long NextUnicodeCharStart;
	long i;
	long j;
	long strlenCharsOfInterest;
	long strlenTerminatorString;
	long Size2Copy;
	long Size2realloc;

	// default output
	OutputBuffer = NULL;
	(*OutputSize) = 0;

	strlenCharsOfInterest = (long)strlen((char *)CharsOfInterest);
	strlenTerminatorString = (long)strlen(TerminatorString);
	if (strlenTerminatorString == 0)
	{
		strlenTerminatorString = 1;		// to support NULL a terminator.
	}

	memset(CharsOfInterestArray, 0, sizeof(CharsOfInterestArray));
	for (i = 0; i < strlenCharsOfInterest; i++)
	{
		CharsOfInterestArray[CharsOfInterest[i]] = 1;
	}

	UnicodeStartStringOffset = StartStringOffset = -1;

	rc = ReadBinaryFileIntoMemory(FileName, (char **)&InputFileBuffer, &SizeOfBuffer, &SizeActuallyRead);

	if (rc == 0)
	{
		OutputBuffer = (char *)malloc(MYSTRINGS_MAXIMUM_FILE_SIZE);
		if (OutputBuffer)
		{
			OutputBufferPos = OutputBuffer;
			for (i = 0; i < (long)SizeActuallyRead - 1; i++)
			{
				// dbg
				if (InputFileBuffer[i] == '‘')
				{
					i = i;
				}
				if (CharsOfInterestArray[InputFileBuffer[i]])
				{
					if (StartStringOffset == -1 && InputFileBuffer[i] != ' ')	// drop leading blanks!
					{
						StartStringOffset = i;
					}
				}
				else
				{
					if (StartStringOffset != -1)
					{
						Size2Copy = i - StartStringOffset;
						if (Size2Copy > MinimumStringSize)
						{
							UnicodeStartStringOffset = -1;
							string temp(reinterpret_cast<char const*>(InputFileBuffer + StartStringOffset), Size2Copy);
							sOutput += temp + "\r\n";
							memcpy(OutputBufferPos, InputFileBuffer + StartStringOffset, Size2Copy);
							OutputBufferPos += Size2Copy;

							memcpy(OutputBufferPos, TerminatorString, strlenTerminatorString);
							OutputBufferPos += strlenTerminatorString;
						}
						StartStringOffset = -1;
					}
				}

				if (UnicodeStartStringOffset >= 0)
				{
					if (i == NextUnicodeCharStart)
					{
						if (InputFileBuffer[i + 1] != 0 || CharsOfInterestArray[InputFileBuffer[i]] == 0)
						{
							Size2Copy = i - UnicodeStartStringOffset;
							if (Size2Copy / 2 > MinimumStringSize)
							{

								for (j = UnicodeStartStringOffset; j < i; j += 2)
								{
									OutputBufferPos[0] = InputFileBuffer[j];
									OutputBufferPos++;
								}

								memcpy(OutputBufferPos, TerminatorString, strlenTerminatorString);
								OutputBufferPos += strlenTerminatorString;
							}
							UnicodeStartStringOffset = -1;
						}

						NextUnicodeCharStart += 2;
					}
				}
				else
				{
					// dbg
					if (InputFileBuffer[i + 1] == 0 && CharsOfInterestArray[InputFileBuffer[i]] && InputFileBuffer[i] != ' ')
					{
						UnicodeStartStringOffset = i;
						NextUnicodeCharStart = i + 2;
					}
				}
			}

			if (StartStringOffset != -1)
			{
				if (Size2Copy > MinimumStringSize)
				{
					Size2Copy = i - StartStringOffset;
					memcpy(OutputBufferPos, InputFileBuffer + StartStringOffset, Size2Copy);
					OutputBufferPos += Size2Copy;
				}
			}

			if (UnicodeStartStringOffset >= 0)
			{
				Size2Copy = i - UnicodeStartStringOffset;
				if (Size2Copy / 2 > MinimumStringSize)
				{
					for (j = UnicodeStartStringOffset; j < i; j += 2)
					{
						OutputBufferPos[0] = InputFileBuffer[j];
						OutputBufferPos++;
					}
				}
			}

		

		}
		memcpy(OutputBufferPos, TerminatorString, strlenTerminatorString);
		OutputBufferPos += strlenTerminatorString;
	}

	if (InputFileBuffer)
	{
		free(InputFileBuffer);
	}

	if (OutputBuffer)
	{
		// perform "safe" realloc.
		Size2realloc = (long)(OutputBufferPos - OutputBuffer);
		(*OutputSize) = Size2realloc;
		OutputBufferPos = OutputBuffer;
		OutputBuffer = (char *)realloc(OutputBuffer, Size2realloc);
		if (OutputBuffer == NULL)
		{
			// realloc failed - restore original address.
			OutputBuffer = OutputBufferPos;
		}
	}

	return(OutputBuffer);

}

long StringsExtractor::ReadBinaryFileIntoMemory(CHAR *CandidateFile, CHAR **FileBuffer, DWORD *SizeOfBuffer, DWORD *SizeActuallyRead)
{
	long rc;
	DWORD SizeToRead;
	WCHAR wcCandidateFile[1024];

	(*FileBuffer) = NULL;
	(*SizeActuallyRead) = 0;
	(*SizeOfBuffer) = 0;

	rc = MyGetFileSizeFromName(CandidateFile, &SizeToRead);

	if (rc)
	{
		return(rc);
	}

	(*FileBuffer) = (CHAR *)malloc(SizeToRead + 2);
	if ((*FileBuffer) == NULL)
	{
		return(MYSTRINGS_MEMORY_ALLOCATION_FAILURE);
	}

	(*SizeOfBuffer) = SizeToRead + 2;

	swprintf_s(wcCandidateFile, sizeof(wcCandidateFile) / 2, L"%S", CandidateFile);

	rc = ReadBinaryFileIntoMemory(wcCandidateFile, *FileBuffer, *SizeOfBuffer, SizeActuallyRead);

	if (rc)
	{
		free((*FileBuffer));
		(*FileBuffer) = NULL;
		(*SizeActuallyRead) = 0;
		(*SizeOfBuffer) = 0;
	}

	return(rc);
}

long StringsExtractor::ReadBinaryFileIntoMemory(WCHAR *CandidateFile, CHAR *FileBuffer, DWORD SizeOfBuffer, DWORD *SizeActuallyRead)
{
	DWORD rc = 0;
	HANDLE hFileToRead;

	DWORD dwBytesRead;
	DWORD SizeToRead;

	FileBuffer[0] = 0;
	*SizeActuallyRead = 0;

	hFileToRead = CreateFileW(CandidateFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileToRead == INVALID_HANDLE_VALUE)
	{
		return(-2);
	}

	SizeToRead = SizeOfBuffer - 1;

	if (ReadFile(hFileToRead, FileBuffer, SizeToRead, &dwBytesRead, NULL) == FALSE)
	{
		dwBytesRead = 0;
	}

	*SizeActuallyRead = dwBytesRead;

	FileBuffer[dwBytesRead] = 0;

	CloseHandle(hFileToRead);

	return(rc);

}



long StringsExtractor::MyGetFileSizeFromName(CHAR *CandidateFile, DWORD *FileSize)
{
	FILE *file;
	errno_t Err;

	(*FileSize) = 0;

	if (Err = fopen_s(&file, CandidateFile, "rb"))
	{
		return(MYSTRINGS_FAILED_TO_OPEN_FILE);
	}
	else
	{
		(*FileSize) = MyGetFileSize(file);
		fclose(file);
		return(MYSTRINGS_OK);
	}
}

long StringsExtractor::MyGetFileSize(FILE *f)
{
	DWORD FileSize;

	fseek(f, 0, SEEK_END); // seek to end of file
	FileSize = (DWORD)ftell(f); // get current file pointer
	fseek(f, 0, SEEK_SET); // seek back to beginning of file

	return(FileSize);
}

