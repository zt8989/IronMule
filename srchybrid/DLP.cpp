//this file is part of eMule Xtreme-Mod (http://www.xtreme-mod.net)
//Copyright (C)2002-2007 Xtreme-Mod (emulextreme@yahoo.de)

//emule Xtreme is a modification of eMule
//Copyright (C)2002-2007 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / http://www.emule-project.net )
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

//
//
//	Author: Xman 
//  





#include "stdafx.h"
#include "DLP.h"
#include "Log.h"
//X-Ray :: Fincan Hash Detection :: Start
#include "opcodes.h"
#include "resource.h"
#include "friend.h"
#include "OtherFunctions.h"
#include "HttpDownloadDlg.h"
#include "SafeFile.h"
//X-Ray :: Fincan Hash Detection :: End

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CDLP::CDLP(CString appdir_in, CString configdir_in)
{
	appdir=appdir_in;
	configdir=configdir_in;

	dlpavailable=false;
	dlpInstance=NULL;
	Reload();
}

CDLP::~CDLP()
{
	if(dlpInstance!=NULL)
	{
		::FreeLibrary(dlpInstance);
	}
}

void CDLP::Reload()
{
	dlpavailable=false;
	bool waserror=false;

	CString newdll=configdir + _T("antiLeech.dll.new");  
    CString olddll=configdir + _T("antiLeech.dll.old");  
    CString currentdll=configdir + _T("antiLeech.dll");  

    CString newdll_legacy=appdir + _T("antiLeech.dll.new");  
    CString olddll_legacy=appdir + _T("antiLeech.dll.old");  
    CString currentdll_legacy=appdir + _T("antiLeech.dll");  

	if(PathFileExists(newdll))
	{
		AddLogLine(false,_T("found new version of antiLeech.dll"));
		//new version exists, try to unload the old and load the new one
		if(dlpInstance!=NULL)
		{
			::FreeLibrary(dlpInstance);
			dlpInstance=NULL;
		}
		if(PathFileExists(currentdll))
		{
			if(PathFileExists(olddll))
			{
				if(_tremove(olddll)!=0)
					waserror=true;
			}
			if(waserror==false)
				if(_trename(currentdll,olddll)!=0)
					waserror=true;
		}
		if(waserror==false)
		{
			if(_trename(newdll,currentdll)!=0)
				waserror=true;
		}
		if(waserror)
			AddLogLine(false,_T("error during copying the antiLeech.dll's, try to load the old one"));

		if(PathFileExists(newdll_legacy) && _tremove(newdll_legacy)!=0)  
            AddLogLine(true,_T("Also found new version of antiLeech.dll in appdir but couldn't remove antiLeech.dll.new from there. Please remove it manually from %s!"),appdir);  
        if(PathFileExists(currentdll_legacy) && _tremove(currentdll_legacy)!=0)  
            AddLogLine(true,_T("Couldn't remove antiLeech.dll from appdir after importing. Please remove it manually from %s!"),appdir);  
        if(PathFileExists(olddll_legacy) && _tremove(olddll_legacy)!=0)  
            AddLogLine(true,_T("Couldn't remove antiLeech.dll.old from appdir after importing. Please remove it manually from %s!"),appdir);  
    }  
    else if(PathFileExists(newdll_legacy))  
    {  
        AddLogLine(false,_T("found new version of antiLeech.dll in appdir, attempting import"));  
        //new version exists in appdir, try to unload the old and load the new one  
        if(dlpInstance!=NULL)  
        {  
            ::FreeLibrary(dlpInstance);  
            dlpInstance=NULL;  
        }  
        if(PathFileExists(currentdll))  
        {  
            if(PathFileExists(olddll))  
            {  
                if(_tremove(olddll)!=0)  
                    waserror=true;  
            }  
            if(waserror==false)  
                if(_trename(currentdll,olddll)!=0)  
                    waserror=true;  
        }  
        if(waserror==false)  
        {  
            if(CopyFile(newdll_legacy,currentdll,TRUE)==0)  
                waserror=true;  
        }  
        if(waserror)  
            AddLogLine(false,_T("error during copying the antiLeech.dll's, try to load the old one"));  
        else  
        {  
            if(_tremove(newdll_legacy)!=0)  
                AddLogLine(true,_T("Couldn't remove newly imported antiLeech.dll.new from appdir after importing. Please remove it manually from %s!"),appdir);  
            if(PathFileExists(currentdll_legacy) && _tremove(currentdll_legacy)!=0)  
                AddLogLine(true,_T("Couldn't remove antiLeech.dll from appdir after importing. Please remove it manually from %s!"),appdir);  
            if(PathFileExists(olddll_legacy) && _tremove(olddll_legacy)!=0)  
                AddLogLine(true,_T("Couldn't remove antiLeech.dll.old from appdir after importing. Please remove it manually from %s!"),appdir);  
        }  
    }  
   
    if(PathFileExists(currentdll_legacy) && !PathFileExists(currentdll))  
    {  
        AddLogLine(false,_T("found antiLeech.dll in appdir but not in configdir, attempting import"));  
        //found dll in appdir but not in configdir, trying to import  
        if(dlpInstance!=NULL)  
        {  
            ::FreeLibrary(dlpInstance);  
            dlpInstance=NULL;  
            AddLogLine(false,_T("dlpInstance was available when importing antileech.dll from appdir (%s) into configdir (%s), shouldn't happen"),appdir,configdir);  
        }  
        if(waserror==false)  
        {  
            if(CopyFile(currentdll_legacy,currentdll,TRUE)==0)  
                waserror=true;  
        }  
        if(waserror)  
             AddLogLine(false,_T("error during copying the antiLeech.dll's, try copying it from appdir to configdir, manually"));  
        else  
        {  
            if(_tremove(currentdll_legacy)!=0)  
                AddLogLine(true,_T("Couldn't remove newly imported antiLeech.dll from appdir after importing. Please remove it manually from %s!"),appdir);  
            if(PathFileExists(olddll_legacy) && _tremove(olddll_legacy)!=0)  
                AddLogLine(true,_T("Couldn't remove antiLeech.dll.old from appdir after importing. Please remove it manually from %s!"),appdir);  
        } 
	}

	if(dlpInstance==NULL)
	{
		dlpInstance=::LoadLibrary(currentdll);
		if(dlpInstance!=NULL)
		{
			//testfunc = (TESTFUNC)GetProcAddress(dlpInstance,("TestFunc"));
			GetDLPVersion = (GETDLPVERSION)GetProcAddress(dlpInstance,("GetDLPVersion"));
			DLPCheckModstring_Hard = (DLPCHECKMODSTRING_HARD)GetProcAddress(dlpInstance,("DLPCheckModstring_Hard"));
			DLPCheckModstring_Soft = (DLPCHECKMODSTRING_SOFT)GetProcAddress(dlpInstance,("DLPCheckModstring_Soft"));

			DLPCheckUsername_Hard = (DLPCHECKUSERNAME_HARD)GetProcAddress(dlpInstance,("DLPCheckUsername_Hard"));
			DLPCheckUsername_Soft = (DLPCHECKUSERNAME_SOFT)GetProcAddress(dlpInstance,("DLPCheckUsername_Soft"));

			DLPCheckNameAndHashAndMod = (DLPCHECKNAMEANDHASHANDMOD)GetProcAddress(dlpInstance,("DLPCheckNameAndHashAndMod"));

			DLPCheckMessageSpam = (DLPCHECKMESSAGESPAM)GetProcAddress(dlpInstance,("DLPCheckMessageSpam"));
			DLPCheckUserhash = (DLPCHECKUSERHASH)GetProcAddress(dlpInstance,("DLPCheckUserhash"));

			DLPCheckHelloTag = (DLPCHECKHELLOTAG)GetProcAddress(dlpInstance,("DLPCheckHelloTag"));
			DLPCheckInfoTag = (DLPCHECKINFOTAG)GetProcAddress(dlpInstance,("DLPCheckInfoTag"));
			if( GetDLPVersion &&
				DLPCheckModstring_Hard &&
				DLPCheckModstring_Soft &&
				DLPCheckUsername_Hard &&
				DLPCheckUsername_Soft &&
				DLPCheckNameAndHashAndMod &&
				DLPCheckHelloTag &&
				DLPCheckInfoTag &&
				DLPCheckMessageSpam &&
				DLPCheckUserhash
				)
			{
				dlpavailable=true;
				AddLogLine(false,_T("Dynamic Anti-Leecher Protection v %u loaded"), GetDLPVersion());
			}
			else
			{
				LogError(_T("failed to initialize the antiLeech.dll, please use an up tp date version of DLP"));
				::FreeLibrary(dlpInstance);
				dlpInstance=NULL;
			}
		}
		else
		{
			LogError(_T("failed to load the antiLeech.dll"));
			LogError(_T("ErrorCode: %u"), GetLastError());
		}
	}
	else
	{
		AddDebugLogLine(false,_T("no new version of antiLeech.dll found. kept the old one"));
		dlpavailable=true;
	}
}

//X-Ray :: Fincan Hash Detection :: Start
bool CDLP::CheckForFincanHash(CString strHash)
{
	return !m_FincanHashList.IsEmpty() && (m_FincanHashList.Find(strHash) != NULL);
}

void CDLP::LoadFincanHashes(CString strURL, bool forced)
{
	if(!forced && !m_FincanHashList.IsEmpty())
		return;

	m_FincanHashList.RemoveAll();

	if(strURL.IsEmpty()) 
		strURL = L"http://www.e-sipa.de/fincan/emfriends.met";

	if(strURL.Find(L"://") == -1){ // not a valid URL
		AddLogLine(true, L"%s: %s", GetResString(IDS_INVALIDURL), strURL);
		return;
	}

	CString strTempFilename;
	strTempFilename.Format(L"%stemp-%d-FincanHashes.met", appdir, ::GetTickCount());

	CHttpDownloadDlg dlgDownload;
	dlgDownload.m_strTitle = L"Downloading Fincan emfirends.met";
	dlgDownload.m_sURLToDownload = strURL;
	dlgDownload.m_sFileToDownloadInto = strTempFilename;

	if (dlgDownload.DoModal() != IDOK){
		AddDebugLogLine(false, L"Failed to load Fincan emfriends.met!");
		return;
	}

	CSafeBufferedFile file;
	CFileException fexp;
	if (!file.Open(strTempFilename, CFile::modeRead | CFile::osSequentialScan | CFile::typeBinary | CFile::shareDenyWrite, &fexp)){
		if (fexp.m_cause != CFileException::fileNotFound){
			CString strError(GetResString(IDS_ERR_READEMFRIENDS));
			TCHAR szError[MAX_CFEXP_ERRORMSG];
			if (fexp.GetErrorMessage(szError, _countof(szError)))
				strError.AppendFormat(L" - %s", szError);
			AddDebugLogLine(false, L"%s", strError);
		}
		_tremove(strTempFilename);
		return;
	}

	try {
		uint8 header = file.ReadUInt8();
		if (header != MET_HEADER){
			file.Close();
			_tremove(strTempFilename);
			return;
		}

		UINT nRecordsNumber = file.ReadUInt32();
		for (UINT i = 0; i < nRecordsNumber; ++i){
			CFriend* Record = new CFriend();
			Record->LoadFromFile(&file);
			if(Record->HasUserhash()){
				const CString strHash = md4str(Record->m_abyUserhash);
				if(!m_FincanHashList.Find(strHash))
					m_FincanHashList.AddTail(strHash);
			}
			delete Record;
		}
		file.Close();
		_tremove(strTempFilename);
	}
	
	catch(CFileException* error){
		if (error->m_cause == CFileException::endOfFile)
			AddDebugLogLine(false, GetResString(IDS_ERR_EMFRIENDSINVALID));
		else {
			TCHAR buffer[MAX_CFEXP_ERRORMSG];
			error->GetErrorMessage(buffer, _countof(buffer));
			AddDebugLogLine(false, GetResString(IDS_ERR_READEMFRIENDS), buffer);
		}
		error->Delete();
		_tremove(strTempFilename);
		return;
	}

	if(!m_FincanHashList.IsEmpty())
		AddDebugLogLine(false, L"Loaded %u Fincan Userhashes!", m_FincanHashList.GetCount());
}
//X-Ray :: Fincan Hash Detection :: End
