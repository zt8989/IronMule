//this file is part of eMule
//Copyright (C)2002-2008 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / http://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

#include "stdafx.h"

int _tmain(int argc, _TCHAR *argv[])
{
	PathStripPath(argv[0]);
	PathRemoveExtension(argv[0]);
	_tcsupr(argv[0]);

	bool errflag = false;
	bool bVerbose = false;
	bool bSetDynamicBase = false;
	bool bSetNXCompat = false;
	int c;
	for (c = 1; !errflag &&  c < argc - 1; c++)
	{
		if (_tcsicmp(argv[c], _T("/verbose")) == 0)
			bVerbose = true;
		else if (_tcsicmp(argv[c], _T("/dynamicbase")) == 0)
			bSetDynamicBase = true;
		else if (_tcsicmp(argv[c], _T("/nxcompat")) == 0)
			bSetNXCompat = true;
		else
			break;
	}

	if (c+1 != argc || errflag) {
		_tprintf(_T("Usage: %s [/dynamicbase | /nxcompat | /verbose] <exe-file>\n"), argv[0]);
		return EXIT_FAILURE;
	}

	_TCHAR *pszFilePath = argv[c];

	LOADED_IMAGE LoadedImage;
	if (!MapAndLoad(pszFilePath, NULL, &LoadedImage, FALSE, FALSE)) {
		_ftprintf(stderr, _T("%s: Error: Failed to load \"%s\"\n"), argv[0], pszFilePath);
		return EXIT_FAILURE;
	}

	int iResult = EXIT_FAILURE;
	if (   LoadedImage.FileHeader
		&& memcmp(&LoadedImage.FileHeader->Signature, "PE\0\0", 4) == 0
		&& LoadedImage.FileHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		if (bVerbose)
		{
			_tprintf(_T("File Header Characteristics\n"));
			_tprintf(_T("  RELOCS_STRIPPED: %d\n"), !!(LoadedImage.FileHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED));
			_tprintf(_T("Optional Header DLL Characteristics\n"));
			_tprintf(_T("  DYNAMIC_BASE:    %d\n"), !!(LoadedImage.FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE));
			_tprintf(_T("  NX_COMPAT:       %d\n"), !!(LoadedImage.FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT));
		}

		if (bSetDynamicBase)
		{
			// VS2003: Linking with "/FIXED" (which is the default for EXE files), strips all relocations.
			// VS2003: Linking with "/FIXED:NO" keeps the relocations.
			if ((LoadedImage.FileHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)
				_ftprintf(stderr, _T("%s: Warning: 'DYNAMIC_BASE' will not have any effect unless EXE file gets linked with '/FIXED:NO'.\n"), argv[0]);

			// Setting the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag for an VS2003 exe-file is
			// exactly the same as when using the VS2005(!) linker and performing a:
			//
			//	>link /edit /dynamicbase <exefile>
			//
			// The VS2005 linker when used as shown above just sets the IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
			// flag. It also updates the CRC checksum of the EXE file, but apart from that there are no other
			// modifications done in the EXE file. So, it is safe for EditBinX to use the Windows API for
			// setting just that flag in the EXE file header.
			if (bVerbose)
				_tprintf(_T("Setting DYNAMIC_BASE\n"));
			LoadedImage.FileHeader->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		}

		if (bSetNXCompat)
		{
			// Could also set NXCOMPAT here, but this would lead to a DEP-Policy of 00000003 (PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION).
			// NOTE: PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION is *not* to be used for a VS2003 application which is using ATL 7.1!
			if (bVerbose)
				_tprintf(_T("Setting NX_COMPAT\n"));
			LoadedImage.FileHeader->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
		}

		iResult = EXIT_SUCCESS;
	}
	else
	{
		_ftprintf(stderr, _T("%s: Error: Invalid EXE file header in \"%s\"\n"), argv[0], pszFilePath);
	}

	if (!UnMapAndLoad(&LoadedImage)) {
		_ftprintf(stderr, _T("%s: Error: Failed to unload \"%s\"\n"), argv[0], pszFilePath);
		return EXIT_FAILURE;
	}

	return iResult;
}
