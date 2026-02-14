//this file is part of eMule
//Copyright (C)2002-2026 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
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
#include "emule.h"
#include "ListenSocket.h"
#include "opcodes.h"
#include "UpDownClient.h"
#include "ClientList.h"
#include "DownloadQueue.h"
#include "Statistics.h"
#include "IPFilter.h"
#include "SharedFileList.h"
#include "PartFile.h"
#include "SafeFile.h"
#include "Packets.h"
#include "UploadQueue.h"
#include "ServerList.h"
#include "Server.h"
#include "ServerConnect.h"
#include "emuledlg.h"
#include "TransferDlg.h"
#include "ClientListCtrl.h"
#include "Exceptions.h"
#include "Kademlia/Utils/uint128.h"
#include "Kademlia/Kademlia/kademlia.h"
#include "Kademlia/Kademlia/prefs.h"
#include "ClientUDPSocket.h"
#include "SHAHashSet.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// CClientReqSocket

IMPLEMENT_DYNCREATE(CClientReqSocket, CEMSocket)

CClientReqSocket::CClientReqSocket(CUpDownClient *in_client)
	: deltimer()
	, m_nOnConnect(SS_Other)
	, deletethis()
	, m_bPortTestCon()
{
	SetClient(in_client);
	theApp.listensocket->AddSocket(this);
	ResetTimeOutTimer();
}

void CClientReqSocket::SetConState(SocketState val)
{
	//If no change, do nothing.
	if ((uint32)val == m_nOnConnect)
		return;
	//Decrease count for the old state
	switch (m_nOnConnect) {
	case SS_Half:
		--theApp.listensocket->m_nHalfOpen;
		break;
	case SS_Complete:
		--theApp.listensocket->m_nComp;
	}
	//Set the new state
	m_nOnConnect = val;
	//Increase count for the new state
	switch (m_nOnConnect) {
	case SS_Half:
		++theApp.listensocket->m_nHalfOpen;
		break;
	case SS_Complete:
		++theApp.listensocket->m_nComp;
	}
}

void CClientReqSocket::WaitForOnConnect()
{
	SetConState(SS_Half);
}

CClientReqSocket::~CClientReqSocket()
{
	//This will update our statistics.
	SetConState(SS_Other);
	if (client)
		client->socket = 0;
	client = NULL;
	theApp.listensocket->RemoveSocket(this);

	DEBUG_ONLY(theApp.clientlist->Debug_SocketDeleted(this));
}

void CClientReqSocket::SetClient(CUpDownClient *pClient)
{
	client = pClient;
	if (client)
		client->socket = this;
}

void CClientReqSocket::ResetTimeOutTimer()
{
	timeout_timer = ::GetTickCount();
}

bool CClientReqSocket::CheckTimeOut()
{
	const DWORD curTick = ::GetTickCount();
	if (m_nOnConnect == SS_Half) {
		//This socket is still in a half connection state. Because of SP2, we don't know
		//if this socket is actually failing, or if this socket is just queued in SP2's new
		//protection queue. Therefore we give the socket a chance to either finally report
		//the connection error, or finally make it through SP2's new queued socket system.
		if (curTick < timeout_timer + CEMSocket::GetTimeOut() * 4)
			return false;
		timeout_timer = curTick;
		CString str;
		str.Format(_T("Timeout: State:%u = SS_Half"), m_nOnConnect);
		Disconnect(str);
		return true;
	}
	DWORD uTimeout = GetTimeOut();
	if (client)
		if (client->GetKadState() == KS_CONNECTED_BUDDY)
			uTimeout += MIN2MS(15);
		else if (client->IsDownloading() && curTick < client->GetUpStartTime() + 4 * CONNECTION_TIMEOUT)
			//TCP flow control might need more time to begin throttling for slow peers
			uTimeout += 4 * CONNECTION_TIMEOUT; //2'30" or slightly more
		else if (client->GetChatState() != MS_NONE)
			//We extend the timeout time here to avoid chatting people from disconnecting too fast.
			uTimeout += CONNECTION_TIMEOUT;

	if (curTick < timeout_timer + uTimeout)
		return false;
	timeout_timer = curTick;
	CString str;
	str.Format(_T("Timeout: State:%u (0 = SS_Other, 1 = SS_Half, 2 = SS_Complete)"), m_nOnConnect);
	Disconnect(str);
	return true;
}

void CClientReqSocket::OnClose(int nErrorCode)
{
	ASSERT(theApp.listensocket->IsValidSocket(this));
	CEMSocket::OnClose(nErrorCode);

	if (nErrorCode)
		Disconnect(thePrefs.GetVerbose() ? GetErrorMessage(nErrorCode, 1) : NULL);
	else
		Disconnect(_T("Close"));
}

void CClientReqSocket::Disconnect(LPCTSTR pszReason)
{
	CEMSocket::SetConState(EMS_DISCONNECTED);
	AsyncSelect(FD_CLOSE);
	if (client) {
		CString sMsg;
		sMsg.Format(_T("CClientReqSocket::Disconnect(): %s"), pszReason);
		if (client->Disconnected(sMsg, true)) {
			const CUpDownClient *temp = client;
			client->socket = NULL;
			client = NULL;
			delete temp;
		} else
			client = NULL;
	}
	Safe_Delete();
}

void CClientReqSocket::Delete_Timed()
{
// it seems that MFC Sockets call socket functions after they are deleted, even if the socket is closed
// and select(0) is set. So we need to wait some time to make sure this doesn't happen
// we currently also rely on this for multithreading; rework synchronization if this ever changes
	if (::GetTickCount() >= deltimer + SEC2MS(10))
		delete this;
}

void CClientReqSocket::Safe_Delete()
{
	ASSERT(theApp.listensocket->IsValidSocket(this));
	CEMSocket::SetConState(EMS_DISCONNECTED);
	AsyncSelect(FD_CLOSE);
	deltimer = ::GetTickCount();
	if (m_SocketData.hSocket != INVALID_SOCKET) // deadlake PROXYSUPPORT - changed to AsyncSocketEx
		ShutDown(CAsyncSocket::both);
	if (client) {
		client->socket = NULL;
		client = NULL;
	}
	deletethis = true;
}

void CClientReqSocket::ProcessPacket(const BYTE *packet, uint32 size, UINT opcode)
{
	switch (opcode) {
	case OP_HELLOANSWER:
		theStats.AddDownDataOverheadOther(size);
		client->ProcessHelloAnswer(packet, size);
		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			DebugRecv("OP_HelloAnswer", client);
			Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetClientInfo());
		}

		// start secure identification, if
		//  - we have received OP_EMULEINFO and OP_HELLOANSWER (old eMule)
		//	- we have received eMule-OP_HELLOANSWER (new eMule)
		if (client->GetInfoPacketsReceived() == IP_BOTH)
			client->InfoPacketsReceived();

		if (client) {
			client->ConnectionEstablished();
			theApp.emuledlg->transferwnd->GetClientList()->RefreshClient(client);
		}
		return;
	case OP_HELLO:
		{
			theStats.AddDownDataOverheadOther(size);

			bool bNewClient = !client;
			if (bNewClient)
				// create new client to save standard information
				client = new CUpDownClient(this);

			bool bIsMuleHello;
			try {
				bIsMuleHello = client->ProcessHelloPacket(packet, size);
			} catch (...) {
				if (bNewClient) {
					// Don't let CUpDownClient::Disconnected process a client which is not in the list of clients.
					delete client;
					client = NULL;
				}
				throw;
			}

			if (thePrefs.GetDebugClientTCPLevel() > 0) {
				DebugRecv("OP_Hello", client);
				Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetClientInfo());
			}

			// now we check if we know this client already. if yes this socket will
			// be attached to the known client, the new client will be deleted
			// and the var. "client" will point to the known client.
			// if not we keep our new-constructed client ;)
			if (theApp.clientlist->AttachToAlreadyKnown(&client, this))
				// update the old client informations
				bIsMuleHello = client->ProcessHelloPacket(packet, size);
			else {
				theApp.clientlist->AddClient(client);
				client->SetCommentDirty();
			}

			theApp.emuledlg->transferwnd->GetClientList()->RefreshClient(client);

			// send a response packet with standard informations
			if (client->GetHashType() == SO_EMULE && !bIsMuleHello)
				client->SendMuleInfoPacket(false);

			client->SendHelloAnswer();

			if (client)
				client->ConnectionEstablished();

			ASSERT(client);
			if (client) {
				// start secure identification, if
				//	- we have received eMule-OP_HELLO (new eMule)
				if (client->GetInfoPacketsReceived() == IP_BOTH)
					client->InfoPacketsReceived();

				if (client->GetKadPort() && client->GetKadVersion() >= KADEMLIA_VERSION2_47a)
					Kademlia::CKademlia::Bootstrap(ntohl(client->GetIP()), client->GetKadPort());
			}
		}
		return;
	case OP_REQUESTFILENAME:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileRequest", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);
			if (size < 16)
				throw GetResString(IDS_ERR_WRONGPACKETSIZE);

			if (!client->GetWaitStartTime())
				client->SetWaitStartTime();

			CSafeMemFile data_in(packet, size);
			uchar reqfilehash[MDX_DIGEST_SIZE];
			data_in.ReadHash16(reqfilehash);

			CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);
			if (reqfile == NULL) {
				reqfile = theApp.downloadqueue->GetFileByID(reqfilehash);
				if (reqfile == NULL || (uint64)((CPartFile*)reqfile)->GetCompletedSize() < PARTSIZE) {
					client->CheckFailedFileIdReqs(reqfilehash);
					return;
				}
			}

			if (reqfile->IsLargeFile() && !client->SupportsLargeFiles()) {
				DebugLogWarning(_T("Client without 64-bit file support requested large file; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
				return;
			}

			// check to see if this is a new file they are asking for
			if (!md4equ(client->GetUploadFileID(), reqfilehash))
				client->SetCommentDirty();
			client->SetUploadFileID(reqfile);

			if (client->ProcessExtendedInfo(data_in, reqfile)) {
				// if we are downloading this file, this could be a new source
				// no passive adding of files with only one part
				if (reqfile->IsPartFile()
					&& (uint64)reqfile->GetFileSize() > PARTSIZE
					&& static_cast<CPartFile*>(reqfile)->GetMaxSources() > static_cast<CPartFile*>(reqfile)->GetSourceCount())
				{
					theApp.downloadqueue->CheckAndAddKnownSource(static_cast<CPartFile*>(reqfile), client, true);
				}

				// send filename etc
				CSafeMemFile data_out(128);
				data_out.WriteHash16(reqfile->GetFileHash());
				data_out.WriteString(reqfile->GetFileName(), client->GetUnicodeSupport());
				Packet *packet1 = new Packet(data_out);
				packet1->opcode = OP_REQFILENAMEANSWER;
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_FileReqAnswer", client, reqfile->GetFileHash());
				theStats.AddUpDataOverheadFileRequest(packet1->size);
				SendPacket(packet1);

				client->SendCommentInfo(reqfile);
			} else {
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_FileReqAnsNoFil", client, packet);
				Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
				md4cpy(replypacket->pBuffer, reqfile->GetFileHash());
				theStats.AddUpDataOverheadFileRequest(replypacket->size);
				SendPacket(replypacket);
				DebugLogWarning(_T("Partcount mismatch on requested file, sending FNF; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
			}
		}
		return;
	case OP_SETREQFILEID:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_SetReqFileID", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			if (size != 16)
				throw GetResString(IDS_ERR_WRONGPACKETSIZE);

			if (!client->GetWaitStartTime())
				client->SetWaitStartTime();

			CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(packet);
			if (!reqfile) {
				reqfile = theApp.downloadqueue->GetFileByID(packet);
				if (reqfile && reqfile->GetPartCount() <= 1)
					reqfile = NULL;
			}
			if (reqfile && (!reqfile->IsLargeFile() || client->SupportsLargeFiles())) {
				// check if this is a new file they are asking for
				if (!md4equ(client->GetUploadFileID(), packet))
					client->SetCommentDirty();

				client->SetUploadFileID(reqfile);

				// send file status
				CSafeMemFile data(16 + 16);
				data.WriteHash16(reqfile->GetFileHash());
				if (reqfile->IsPartFile())
					static_cast<CPartFile*>(reqfile)->WritePartStatus(data);
				else
					data.WriteUInt16(0);
				Packet *packet2 = new Packet(data);
				packet2->opcode = OP_FILESTATUS;
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_FileStatus", client, reqfile->GetFileHash());
				theStats.AddUpDataOverheadFileRequest(packet2->size);
				SendPacket(packet2);
			} else {
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_FileReqAnsNoFil", client, packet);
				Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
				md4cpy(replypacket->pBuffer, packet);
				theStats.AddUpDataOverheadFileRequest(replypacket->size);
				SendPacket(replypacket);
				if (reqfile)
					DebugLogWarning(_T("Client without 64-bit file support requested large file; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
				else
					client->CheckFailedFileIdReqs(packet);
			}
		}
		return;
	case OP_FILEREQANSNOFIL:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileReqAnsNoFil", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);
			if (size != 16)
				throw GetResString(IDS_ERR_WRONGPACKETSIZE);
			CPartFile *rqfile = theApp.downloadqueue->GetFileByID(packet);
			if (rqfile) {
				rqfile->m_DeadSourceList.AddDeadSource(*client);
				// if that client does not have my file maybe has another different
				// we try to swap to another file ignoring no needed parts files
				switch (client->GetDownloadState()) {
				case DS_CONNECTED:
				case DS_ONQUEUE:
				case DS_NONEEDEDPARTS:
					client->DontSwapTo(rqfile); // ZZ:DownloadManager
					if (!client->SwapToAnotherFile(_T("Source says it doesn't have the file. CClientReqSocket::ProcessPacket()"), true, true, true, NULL, false, false)) // ZZ:DownloadManager
						theApp.downloadqueue->RemoveSource(client);
				}
			} else
				client->CheckFailedFileIdReqs(packet);
		}
		return;
	case OP_REQFILENAMEANSWER:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileReqAnswer", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			CSafeMemFile data(packet, size);
			uchar cfilehash[MDX_DIGEST_SIZE];
			data.ReadHash16(cfilehash);
			CPartFile *file = theApp.downloadqueue->GetFileByID(cfilehash);
			if (file == NULL)
				client->CheckFailedFileIdReqs(cfilehash);
			client->ProcessFileInfo(data, file);
		}
		return;
	case OP_FILESTATUS:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FileStatus", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			CSafeMemFile data(packet, size);
			uchar cfilehash[MDX_DIGEST_SIZE];
			data.ReadHash16(cfilehash);
			CPartFile *file = theApp.downloadqueue->GetFileByID(cfilehash);
			if (file == NULL)
				client->CheckFailedFileIdReqs(cfilehash);
			client->ProcessFileStatus(false, data, file);
		}
		return;
	case OP_STARTUPLOADREQ:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_StartUpLoadReq", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);

		if (client->CheckHandshakeFinished() && size == 16) {
			CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(packet);
			if (reqfile) {
				if (!md4equ(client->GetUploadFileID(), packet))
					client->SetCommentDirty();
				client->SetUploadFileID(reqfile);
				client->SendCommentInfo(reqfile);
				theApp.uploadqueue->AddClientToQueue(client);
			} else
				client->CheckFailedFileIdReqs(packet);
		}
		return;
	case OP_QUEUERANK:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_QueueRank", client);
		theStats.AddDownDataOverheadFileRequest(size);
		client->ProcessEdonkeyQueueRank(packet, size);
		return;
	case OP_ACCEPTUPLOADREQ:
		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			DebugRecv("OP_AcceptUploadReq", client, (size >= 16) ? packet : NULL);
			if (size > 0)
				Debug(_T("  ***NOTE: Packet contains %u additional bytes\n"), size);
			Debug(_T("  QR=%d\n"), client->IsRemoteQueueFull() ? UINT_MAX : client->GetRemoteQueueRank());
		}
		theStats.AddDownDataOverheadFileRequest(size);
		client->ProcessAcceptUpload();
		return;
	case OP_REQUESTPARTS:
		{
			// see also OP_REQUESTPARTS_I64
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_RequestParts", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			CSafeMemFile data(packet, size);
			uchar reqfilehash[MDX_DIGEST_SIZE];
			data.ReadHash16(reqfilehash);

			uint32 aOffset[3 * 2]; //3 starts, then 3 ends
			for (unsigned i = 0; i < 3 * 2; ++i)
				aOffset[i] = data.ReadUInt32();

			if (thePrefs.GetDebugClientTCPLevel() > 0)
				for (unsigned i = 0; i < 3; ++i)
					Debug(_T("  Start[%u]=%u  End[%u]=%u  Size=%u\n"), i, aOffset[i], i, aOffset[i + 3], aOffset[i + 3] - aOffset[i]);

			for (unsigned i = 0; i < 3; ++i)
				if (aOffset[i] < aOffset[i + 3]) {
					Requested_Block_Struct *reqblock = new Requested_Block_Struct;
					reqblock->StartOffset = aOffset[i];
					reqblock->EndOffset = aOffset[i + 3];
					md4cpy(reqblock->FileID, reqfilehash);
					reqblock->transferred = 0;
					client->AddReqBlock(reqblock, false);
				} else if (thePrefs.GetVerbose() && (aOffset[i + 3] != 0 || aOffset[i] != 0))
					DebugLogWarning(_T("Client requests invalid %u. file block %u-%u (%d bytes): %s"), i, aOffset[i], aOffset[i + 3], aOffset[i + 3] - aOffset[i], (LPCTSTR)client->DbgGetClientInfo());

				client->AddReqBlock(NULL, true);
		}
		return;
	case OP_CANCELTRANSFER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_CancelTransfer", client);
		theStats.AddDownDataOverheadFileRequest(size);
		theApp.uploadqueue->RemoveFromUploadQueue(client, _T("Remote client cancelled transfer."));
		return;
	case OP_END_OF_DOWNLOAD:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_EndOfDownload", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);
		if (size >= 16 && md4equ(client->GetUploadFileID(), packet))
			theApp.uploadqueue->RemoveFromUploadQueue(client, _T("Remote client ended transfer."));
		else
			client->CheckFailedFileIdReqs(packet);
		return;
	case OP_HASHSETREQUEST:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_HashSetReq", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);

		if (size != 16)
			throw GetResString(IDS_ERR_WRONGHPACKETSIZE);
		client->SendHashsetPacket(packet, 16, false);
		return;
	case OP_HASHSETANSWER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_HashSetAnswer", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);
		client->ProcessHashSet(packet, size, false);
		return;
	case OP_SENDINGPART:
		{
			// see also OP_SENDINGPART_I64
			if (thePrefs.GetDebugClientTCPLevel() > 1)
				DebugRecv("OP_SendingPart", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(16 + 2 * 4);
			//client->CheckHandshakeFinished();
			EDownloadState newDS = DS_NONE;
			const CPartFile *creqfile = client->GetRequestFile();
			if (creqfile && !creqfile->IsStopped() && inSet(creqfile->GetStatus(), PS_READY, PS_EMPTY)) {
				client->ProcessBlockPacket(packet, size, false, false);
				if (!creqfile->IsStopped() && creqfile->GetStatus() == PS_ERROR)
					newDS = DS_ONQUEUE;
				else
					newDS = DS_CONNECTED; //any state but DS_NONE or DS_ONQUEUE
			}
			if (newDS != DS_CONNECTED && client) { //client could have been deleted while debugging
				client->SendCancelTransfer();
				client->SetDownloadState(newDS);
			}
		}
		return;
	case OP_OUTOFPARTREQS:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_OutOfPartReqs", client);
		theStats.AddDownDataOverheadFileRequest(size);
		if (client->GetDownloadState() == DS_DOWNLOADING)
			client->SetDownloadState(DS_ONQUEUE, _T("The remote client decided to stop/complete the transfer (got OP_OutOfPartReqs)."));
		return;
	case OP_CHANGE_CLIENT_ID:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_ChangedClientID", client);
			theStats.AddDownDataOverheadOther(size);

			CSafeMemFile data(packet, size);
			uint32 nNewUserID = data.ReadUInt32();
			uint32 nNewServerIP = data.ReadUInt32();
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				Debug(_T("  NewUserID=%u (%08x, %s)  NewServerIP=%u (%08x, %s)\n"), nNewUserID, nNewUserID, (LPCTSTR)ipstr(nNewUserID), nNewServerIP, nNewServerIP, (LPCTSTR)ipstr(nNewServerIP));
			if (::IsLowID(nNewUserID)) { // client changed server and has a LowID
				CServer *pNewServer = theApp.serverlist->GetServerByIP(nNewServerIP);
				if (pNewServer != NULL) {
					client->SetUserIDHybrid(nNewUserID); // update UserID only if we know the server
					client->SetServerIP(nNewServerIP);
					client->SetServerPort(pNewServer->GetPort());
				}
			} else if (nNewUserID == client->GetIP()) {	// client changed server and has a HighID(IP)
				client->SetUserIDHybrid(ntohl(nNewUserID));
				CServer *pNewServer = theApp.serverlist->GetServerByIP(nNewServerIP);
				if (pNewServer != NULL) {
					client->SetServerIP(nNewServerIP);
					client->SetServerPort(pNewServer->GetPort());
				}
			} else if (thePrefs.GetDebugClientTCPLevel() > 0)
				Debug(_T("***NOTE: OP_ChangedClientID unknown contents\n"));

			UINT uAddData = (UINT)(data.GetLength() - data.GetPosition());
			if (uAddData > 0 && thePrefs.GetDebugClientTCPLevel() > 0)
				Debug(_T("***NOTE: OP_ChangedClientID contains add. data %s\n"), (LPCTSTR)DbgGetHexDump(packet + data.GetPosition(), uAddData));
		}
		return;
	case OP_CHANGE_SLOT:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_ChangeSlot", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(size);
		// sometimes sent by Hybrid
		return;
	case OP_MESSAGE:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_Message", client);
			theStats.AddDownDataOverheadOther(size);

			if (size < 2)
				throwCStr(_T("invalid message packet"));
			CSafeMemFile data(packet, size);
			UINT length = data.ReadUInt16();
			if (length + 2 != size)
				throwCStr(_T("invalid message packet"));

			if (length > MAX_CLIENT_MSG_LEN) {
				if (thePrefs.GetVerbose())
					AddDebugLogLine(false, _T("Message from '%s' (IP:%s) exceeds limit by %u chars, truncated."), client->GetUserName(), (LPCTSTR)ipstr(client->GetConnectIP()), length - MAX_CLIENT_MSG_LEN);
				length = MAX_CLIENT_MSG_LEN;
			}

			client->ProcessChatMessage(data, length);
		}
		return;
	case OP_ASKSHAREDFILES:
		{
			// client wants to know what we have in share, let's see if we allow him to know that
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedFiles", client);
			theStats.AddDownDataOverheadOther(size);

			CPtrList list;
			if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
				for (const CKnownFilesMap::CPair *pair = theApp.sharedfiles->m_Files_map.PGetFirstAssoc(); pair != NULL; pair = theApp.sharedfiles->m_Files_map.PGetNextAssoc(pair))
					if (!pair->value->IsLargeFile() || client->SupportsLargeFiles())
						list.AddTail((void*)pair->value);

				AddLogLine(true, GetResString(IDS_REQ_SHAREDFILES), (LPCTSTR)client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_ACCEPTED));
			} else
				DebugLog(GetResString(IDS_REQ_SHAREDFILES), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_DENIED));

			// now create the memfile for the packet
			CSafeMemFile tempfile(80);
			tempfile.WriteUInt32((uint32)list.GetCount());
			while (!list.IsEmpty())
				theApp.sharedfiles->CreateOfferedFilePacket(reinterpret_cast<CKnownFile*>(list.RemoveHead()), tempfile, NULL, client);

			// create a packet and send it
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugSend("OP_AskSharedFilesAnswer", client);
			Packet *replypacket = new Packet(tempfile);
			replypacket->opcode = OP_ASKSHAREDFILESANSWER;
			theStats.AddUpDataOverheadOther(replypacket->size);
			SendPacket(replypacket, true);
		}
		return;
	case OP_ASKSHAREDFILESANSWER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_AskSharedFilesAnswer", client);
		theStats.AddDownDataOverheadOther(size);
		client->ProcessSharedFileList(packet, size);
		return;
	case OP_ASKSHAREDDIRS:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_AskSharedDirectories", client);
		theStats.AddDownDataOverheadOther(size);

		if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
			AddLogLine(true, GetResString(IDS_SHAREDREQ1), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_ACCEPTED));
			client->SendSharedDirectories();
		} else {
			DebugLog(GetResString(IDS_SHAREDREQ1), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)GetResString(IDS_DENIED));
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugSend("OP_AskSharedDeniedAnswer", client);
			Packet *replypacket = new Packet(OP_ASKSHAREDDENIEDANS, 0);
			theStats.AddUpDataOverheadOther(replypacket->size);
			SendPacket(replypacket, true);
		}
		return;
	case OP_ASKSHAREDFILESDIR:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedFilesInDirectory", client);
			theStats.AddDownDataOverheadOther(size);

			Packet *replypacket;
			CSafeMemFile data(packet, size);
			CString strReqDir(data.ReadString(client->GetUnicodeSupport() != UTF8strNone));
			if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
				AddLogLine(true, GetResString(IDS_SHAREDREQ2), (LPCTSTR)client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strReqDir, (LPCTSTR)GetResString(IDS_ACCEPTED));
				ASSERT(data.GetPosition() == data.GetLength());
				CTypedPtrList<CPtrList, CKnownFile*> list;
				const CString strOrgReqDir(strReqDir);
				if (strReqDir == OP_INCOMPLETE_SHARED_FILES) {
					for (POSITION pos = NULL; ;) { // get all shared files from download queue
						CPartFile *pFile = theApp.downloadqueue->GetFileNext(pos);
						if (pFile && pFile->GetStatus(true) == PS_READY && (!pFile->IsLargeFile() || client->SupportsLargeFiles()))
							list.AddTail(pFile);
						if (pos == NULL)
							break;
					}
				} else {
					bool bSingleSharedFiles = (strReqDir == OP_OTHER_SHARED_FILES);
					if (!bSingleSharedFiles)
						strReqDir = theApp.sharedfiles->GetDirNameByPseudo(strReqDir);
					if (!strReqDir.IsEmpty()) {
						// get all shared files from requested directory
						for (const CKnownFilesMap::CPair *pair = theApp.sharedfiles->m_Files_map.PGetFirstAssoc(); pair != NULL; pair = theApp.sharedfiles->m_Files_map.PGetNextAssoc(pair)) {
							CKnownFile *cur_file = pair->value;
							// all files not in shared directories have to be single shared files
							if (((!bSingleSharedFiles && EqualPaths(strReqDir, cur_file->GetSharedDirectory()))
								|| (bSingleSharedFiles && !theApp.sharedfiles->ShouldBeShared(cur_file->GetSharedDirectory(), NULL, false))
								)
								&& (!cur_file->IsLargeFile() || client->SupportsLargeFiles()))
							{
								list.AddTail(cur_file);
							}
						}
					} else
						DebugLogError(_T("View shared files: Pseudonym for requested Directory (%s) was not found - sending empty result"), (LPCTSTR)strOrgReqDir);
				}

				// Currently we are sending each shared directory, even if it does not contain any files.
				// Because of this we also have to send an empty shared files list.
				CSafeMemFile tempfile(80);
				tempfile.WriteString(strOrgReqDir, client->GetUnicodeSupport());
				tempfile.WriteUInt32((uint32)list.GetCount());
				while (!list.IsEmpty())
					theApp.sharedfiles->CreateOfferedFilePacket(list.RemoveHead(), tempfile, NULL, client);

				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_AskSharedFilesInDirectoryAnswer", client);
				replypacket = new Packet(tempfile);
				replypacket->opcode = OP_ASKSHAREDFILESDIRANS;
			} else {
				DebugLog(GetResString(IDS_SHAREDREQ2), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strReqDir, (LPCTSTR)GetResString(IDS_DENIED));
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_AskSharedDeniedAnswer", client);
				replypacket = new Packet(OP_ASKSHAREDDENIEDANS, 0);
			}
			theStats.AddUpDataOverheadOther(replypacket->size);
			SendPacket(replypacket, true);
		}
		return;
	case OP_ASKSHAREDDIRSANS:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedDirectoriesAnswer", client);
			theStats.AddDownDataOverheadOther(size);
			if (client->GetFileListRequested() == 1) {
				CSafeMemFile data(packet, size);
				uint32 uDirs = data.ReadUInt32();
				for (uint32 i = uDirs; i > 0; --i) {
					const CString &strDir(data.ReadString(client->GetUnicodeSupport() != UTF8strNone));
					// Better send the received and untouched directory string back to that client
					AddLogLine(true, GetResString(IDS_SHAREDANSW), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strDir);

					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP_AskSharedFilesInDirectory", client);
					CSafeMemFile tempfile(80);
					tempfile.WriteString(strDir, client->GetUnicodeSupport());
					Packet *replypacket = new Packet(tempfile);
					replypacket->opcode = OP_ASKSHAREDFILESDIR;
					theStats.AddUpDataOverheadOther(replypacket->size);
					SendPacket(replypacket, true);
				}
				ASSERT(data.GetPosition() == data.GetLength());
				client->SetFileListRequested(uDirs);
			} else
				AddLogLine(true, GetResString(IDS_SHAREDANSW2), client->GetUserName(), client->GetUserIDHybrid());
		}
		return;
	case OP_ASKSHAREDFILESDIRANS:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AskSharedFilesInDirectoryAnswer", client);
			theStats.AddDownDataOverheadOther(size);

			CSafeMemFile data(packet, size);
			CString strDir(data.ReadString(client->GetUnicodeSupport() != UTF8strNone));

			if (client->GetFileListRequested() > 0) {
				AddLogLine(true, GetResString(IDS_SHAREDINFO1), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strDir);
				client->ProcessSharedFileList(packet + data.GetPosition(), (uint32)(size - data.GetPosition()), strDir);
				if (client->GetFileListRequested() == 0)
					AddLogLine(true, GetResString(IDS_SHAREDINFO2), client->GetUserName(), client->GetUserIDHybrid());
			} else
				AddLogLine(true, GetResString(IDS_SHAREDANSW3), client->GetUserName(), client->GetUserIDHybrid(), (LPCTSTR)strDir);
		}
		return;
	case OP_ASKSHAREDDENIEDANS:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_AskSharedDeniedAnswer", client);
		theStats.AddDownDataOverheadOther(size);

		AddLogLine(true, GetResString(IDS_SHAREDREQDENIED), client->GetUserName(), client->GetUserIDHybrid());
		client->SetFileListRequested(0);
		return;
	default:
		theStats.AddDownDataOverheadOther(size);
		PacketToDebugLogLine(_T("eDonkey"), packet, size, opcode);
	}
}

void CClientReqSocket::ProcessExtPacket(const BYTE *packet, uint32 size, UINT opcode, UINT uRawSize)
{
	switch (opcode) {
	case OP_MULTIPACKET: // deprecated
	case OP_MULTIPACKET_EXT: // deprecated
	case OP_MULTIPACKET_EXT2:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				if (opcode == OP_MULTIPACKET)
					DebugRecv("OP_MultiPacket", client, (size >= 16) ? packet : NULL);
				else
					DebugRecv((opcode == OP_MULTIPACKET_EXT2 ? "OP_MultiPacket_Ext2" : "OP_MultiPacket_Ext"), client, (size >= 24) ? packet : NULL);

			theStats.AddDownDataOverheadFileRequest(uRawSize);
			//client->CheckHandshakeFinished();

			if (client->GetKadPort() && client->GetKadVersion() >= KADEMLIA_VERSION2_47a)
				Kademlia::CKademlia::Bootstrap(ntohl(client->GetIP()), client->GetKadPort());

			CSafeMemFile data_in(packet, size);
			CKnownFile *reqfile;
			bool bNotFound = false;
			uchar reqfilehash[MDX_DIGEST_SIZE];
			if (opcode == OP_MULTIPACKET_EXT2) { // file identifier support
				CFileIdentifierSA fileIdent;
				if (!fileIdent.ReadIdentifier(data_in)) {
					DebugLogWarning(_T("Error reading file identifier from MultiPacket_Ext2 - %s"), (LPCTSTR)client->DbgGetClientInfo());
					return;
				}
				md4cpy(reqfilehash, fileIdent.GetMD4Hash()); // need this in case we want to sent a FNF
				reqfile = theApp.sharedfiles->GetFileByID(fileIdent.GetMD4Hash());
				if (reqfile == NULL) {
					reqfile = theApp.downloadqueue->GetFileByID(fileIdent.GetMD4Hash());
					if (reqfile == NULL || (uint64)((CPartFile*)reqfile)->GetCompletedSize() < PARTSIZE) {
						bNotFound = true;
						client->CheckFailedFileIdReqs(fileIdent.GetMD4Hash());
					}
				}
				if (!bNotFound && !reqfile->GetFileIdentifier().CompareRelaxed(fileIdent)) {
					bNotFound = true;
					DebugLogWarning(_T("FileIdentifier Mismatch on requested file, sending FNF; %s, File=\"%s\", Local Ident: %s, Received Ident: %s"), (LPCTSTR)client->DbgGetClientInfo()
						, (LPCTSTR)reqfile->GetFileName(), (LPCTSTR)reqfile->GetFileIdentifier().DbgInfo(), (LPCTSTR)fileIdent.DbgInfo());
				}
			} else { // no file identifier
				data_in.ReadHash16(reqfilehash);
				uint64 nSize = (opcode == OP_MULTIPACKET_EXT) ? data_in.ReadUInt64() : 0;
				reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);
				if (reqfile == NULL) {
					reqfile = theApp.downloadqueue->GetFileByID(reqfilehash);
					if (reqfile == NULL || (uint64)((CPartFile*)reqfile)->GetCompletedSize() < PARTSIZE) {
						bNotFound = true;
						client->CheckFailedFileIdReqs(reqfilehash);
					}
				}
				if (!bNotFound && nSize != 0 && nSize != reqfile->GetFileSize()) {
					bNotFound = true;
					DebugLogWarning(_T("Size Mismatch on requested file, sending FNF; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
				}
			}

			if (!bNotFound && reqfile->IsLargeFile() && !client->SupportsLargeFiles()) {
				bNotFound = true;
				DebugLogWarning(_T("Client without 64bit file support requested large file; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
			}
			if (bNotFound) {
				// send file request answer - no such file packet (0x48)
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_FileReqAnsNoFil", client, packet);
				Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
				md4cpy(replypacket->pBuffer, reqfilehash);
				theStats.AddUpDataOverheadFileRequest(replypacket->size);
				SendPacket(replypacket);
				return;
			}

			if (!client->GetWaitStartTime())
				client->SetWaitStartTime();

			// if we are downloading this file, this could be a new source
			// no passive adding of files with only one part
			if (reqfile->IsPartFile() && (uint64)reqfile->GetFileSize() > PARTSIZE)
				if (static_cast<CPartFile*>(reqfile)->GetMaxSources() > static_cast<CPartFile*>(reqfile)->GetSourceCount())
					theApp.downloadqueue->CheckAndAddKnownSource(static_cast<CPartFile*>(reqfile), client, true);

			// check to see if this is a new file they are asking for
			if (!md4equ(client->GetUploadFileID(), reqfile->GetFileHash()))
				client->SetCommentDirty();

			client->SetUploadFileID(reqfile);

			CSafeMemFile data_out(128);
			if (opcode == OP_MULTIPACKET_EXT2) // file identifier support
				reqfile->GetFileIdentifierC().WriteIdentifier(data_out);
			else
				data_out.WriteHash16(reqfile->GetFileHash());
			bool bAnswerFNF = false;
			while (data_in.GetLength() > data_in.GetPosition() && !bAnswerFNF) {
				uint8 opcode_in = data_in.ReadUInt8();
				switch (opcode_in) {
				case OP_REQUESTFILENAME:
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugRecv("OP_MPReqFileName", client, packet);

					if (!client->ProcessExtendedInfo(data_in, reqfile)) {
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugSend("OP_FileReqAnsNoFil", client, packet);
						Packet *replypacket = new Packet(OP_FILEREQANSNOFIL, 16);
						md4cpy(replypacket->pBuffer, reqfile->GetFileHash());
						theStats.AddUpDataOverheadFileRequest(replypacket->size);
						SendPacket(replypacket);
						DebugLogWarning(_T("Partcount mismatch on requested file, sending FNF; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());
						bAnswerFNF = true;
					} else {
						data_out.WriteUInt8(OP_REQFILENAMEANSWER);
						data_out.WriteString(reqfile->GetFileName(), client->GetUnicodeSupport());
					}
					break;
				case OP_AICHFILEHASHREQ:
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugRecv("OP_MPAichFileHashReq", client, packet);

					if (client->SupportsFileIdentifiers() || opcode == OP_MULTIPACKET_EXT2) // not allowed any more with file idents supported
						DebugLogWarning(_T("Client requested AICH Hash packet, but supports FileIdentifiers, ignored - %s"), (LPCTSTR)client->DbgGetClientInfo());
					else if (client->IsSupportingAICH() && reqfile->GetFileIdentifier().HasAICHHash()) {
						data_out.WriteUInt8(OP_AICHFILEHASHANS);
						reqfile->GetFileIdentifier().GetAICHHash().Write(data_out);
					}
					break;
				case OP_SETREQFILEID:
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugRecv("OP_MPSetReqFileID", client, packet);

					data_out.WriteUInt8(OP_FILESTATUS);
					if (reqfile->IsPartFile())
						static_cast<CPartFile*>(reqfile)->WritePartStatus(data_out);
					else
						data_out.WriteUInt16(0);
					break;
				//We still send the source packet separately.
				case OP_REQUESTSOURCES2:
				case OP_REQUESTSOURCES:
					{
						if (thePrefs.GetDebugClientTCPLevel() > 0)
							DebugRecv(opcode_in == OP_REQUESTSOURCES ? "OP_MPReqSources2" : "OP_MPReqSources", client, packet);

						if (thePrefs.GetDebugSourceExchange())
							AddDebugLogLine(false, _T("SXRecv: Client source request; %s, File=\"%s\""), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)reqfile->GetFileName());

						uint8 byRequestedVersion = 0;
						uint16 byRequestedOptions = 0;
						if (opcode_in == OP_REQUESTSOURCES2) { // SX2 requests contains additional data
							byRequestedVersion = data_in.ReadUInt8();
							byRequestedOptions = data_in.ReadUInt16();
						}
						//Although this shouldn't happen, it's just in case for any Mods that mess with version numbers.
						if (byRequestedVersion > 0 || client->GetSourceExchange1Version() > 1) {
							DWORD dwTimePassed = ::GetTickCount() - client->GetLastSrcReqTime() + CONNECTION_LATENCY;
							bool bNeverAskedBefore = client->GetLastSrcReqTime() == 0;
							if ( //if not complete and file is rare
								(reqfile->IsPartFile()
									&& (bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS)
									&& static_cast<CPartFile*>(reqfile)->GetSourceCount() <= RARE_FILE
								)
									//OR if file is not rare or is complete
								|| bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS * MINCOMMONPENALTY
							   )
							{
								client->SetLastSrcReqTime();
								Packet *tosend = reqfile->CreateSrcInfoPacket(client, byRequestedVersion, byRequestedOptions);
								if (tosend) {
									if (thePrefs.GetDebugClientTCPLevel() > 0)
										DebugSend("OP_AnswerSources", client, reqfile->GetFileHash());
									theStats.AddUpDataOverheadSourceExchange(tosend->size);
									SendPacket(tosend);
								}
							}/* else if (thePrefs.GetVerbose())
								AddDebugLogLine(false, _T("RCV: Source Request too fast. (This is testing the new timers to see how much older client will not receive this)"));
							*/
						}
					}
					break;
				default:
					{
						CString strError;
						strError.Format(_T("Invalid sub opcode 0x%02x received"), opcode_in);
						throw strError;
					}
				}
			}
			if (data_out.GetLength() > 16 && !bAnswerFNF) {
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_MultiPacketAns", client, reqfile->GetFileHash());
				Packet *reply = new Packet(data_out, OP_EMULEPROT);
				reply->opcode = (opcode == OP_MULTIPACKET_EXT2) ? OP_MULTIPACKETANSWER_EXT2 : OP_MULTIPACKETANSWER;
				theStats.AddUpDataOverheadFileRequest(reply->size);
				SendPacket(reply);
			}
		}
		return;
	case OP_MULTIPACKETANSWER:
	case OP_MULTIPACKETANSWER_EXT2:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_MultiPacketAns", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(uRawSize);
			//client->CheckHandshakeFinished();

			if (client->GetKadPort() && client->GetKadVersion() >= KADEMLIA_VERSION2_47a)
				Kademlia::CKademlia::Bootstrap(ntohl(client->GetIP()), client->GetKadPort());

			CSafeMemFile data_in(packet, size);

			CPartFile *reqfile = NULL;
			if (opcode == OP_MULTIPACKETANSWER_EXT2) {
				CFileIdentifierSA fileIdent;
				if (!fileIdent.ReadIdentifier(data_in))
					throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER_EXT2; ReadIdentifier() failed)");
				reqfile = theApp.downloadqueue->GetFileByID(fileIdent.GetMD4Hash());
				if (reqfile == NULL) {
					client->CheckFailedFileIdReqs(fileIdent.GetMD4Hash());
					throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER_EXT2; reqfile==NULL)");
				}
				if (!reqfile->GetFileIdentifier().CompareRelaxed(fileIdent))
					throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER_EXT2; FileIdentifier mismatch)");
				if (fileIdent.HasAICHHash())
					client->ProcessAICHFileHash(NULL, reqfile, &fileIdent.GetAICHHash());
			} else {
				uchar reqfilehash[MDX_DIGEST_SIZE];
				data_in.ReadHash16(reqfilehash);
				reqfile = theApp.downloadqueue->GetFileByID(reqfilehash);
				//Make sure we are downloading this file.
				if (reqfile == NULL) {
					client->CheckFailedFileIdReqs(reqfilehash);
					throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER; reqfile==NULL)");
				}
			}
			if (client->GetRequestFile() == NULL)
				throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER; client->GetRequestFile()==NULL)");
			if (reqfile != client->GetRequestFile())
				throw GetResString(IDS_ERR_WRONGFILEID) + _T(" (OP_MULTIPACKETANSWER; reqfile!=client->GetRequestFile())");
			while (data_in.GetLength() > data_in.GetPosition()) {
				uint8 opcode_in = data_in.ReadUInt8();
				switch (opcode_in) {
				case OP_REQFILENAMEANSWER:
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugRecv("OP_MPReqFileNameAns", client, packet);

					client->ProcessFileInfo(data_in, reqfile);
					break;
				case OP_FILESTATUS:
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugRecv("OP_MPFileStatus", client, packet);

					client->ProcessFileStatus(false, data_in, reqfile);
					break;
				case OP_AICHFILEHASHANS:
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugRecv("OP_MPAichFileHashAns", client);

					client->ProcessAICHFileHash(&data_in, reqfile, NULL);
					break;
				default:
					{
						CString strError;
						strError.Format(_T("Invalid sub opcode 0x%02x received"), opcode_in);
						throw strError;
					}
				}
			}
		}
		return;
	case OP_EMULEINFO:
		theStats.AddDownDataOverheadOther(uRawSize);
		client->ProcessMuleInfoPacket(packet, size);
		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			DebugRecv("OP_EmuleInfo", client);
			Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetMuleInfo());
		}

		// start secure identification, if
		//  - we have received eD2K and eMule info (old eMule)
		if (client->GetInfoPacketsReceived() == IP_BOTH)
			client->InfoPacketsReceived();

		client->SendMuleInfoPacket(true);
		return;
	case OP_EMULEINFOANSWER:
		theStats.AddDownDataOverheadOther(uRawSize);
		client->ProcessMuleInfoPacket(packet, size);
		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			DebugRecv("OP_EmuleInfoAnswer", client);
			Debug(_T("  %s\n"), (LPCTSTR)client->DbgGetMuleInfo());
		}

		// start secure identification, if
		//  - we have received eD2K and eMule info (old eMule)
		if (client->GetInfoPacketsReceived() == IP_BOTH)
			client->InfoPacketsReceived();
		return;
	case OP_SECIDENTSTATE:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_SecIdentState", client);
		theStats.AddDownDataOverheadOther(uRawSize);

		client->ProcessSecIdentStatePacket(packet, size);
		if (client->GetSecureIdentState() == IS_SIGNATURENEEDED)
			client->SendSignaturePacket();
		else if (client->GetSecureIdentState() == IS_KEYANDSIGNEEDED) {
			client->SendPublicKeyPacket();
			client->SendSignaturePacket();
		}
		return;
	case OP_PUBLICKEY:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_PublicKey", client);
		theStats.AddDownDataOverheadOther(uRawSize);

		client->ProcessPublicKeyPacket(packet, size);
		return;
	case OP_SIGNATURE:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_Signature", client);
		theStats.AddDownDataOverheadOther(uRawSize);

		client->ProcessSignaturePacket(packet, size);
		return;
	case OP_QUEUERANKING:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_QueueRanking", client);
		theStats.AddDownDataOverheadFileRequest(uRawSize);
		//client->CheckHandshakeFinished();

		client->ProcessEmuleQueueRank(packet, size);
		return;
	case OP_REQUESTSOURCES2:
	case OP_REQUESTSOURCES:
		{
			CSafeMemFile data(packet, size);
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv(opcode == OP_REQUESTSOURCES2 ? "OP_MPReqSources2" : "OP_MPReqSources", client, (size >= 16) ? packet : NULL);

			theStats.AddDownDataOverheadSourceExchange(uRawSize);
			//client->CheckHandshakeFinished();

			uint8 byRequestedVersion = 0;
			uint16 byRequestedOptions = 0;
			if (opcode == OP_REQUESTSOURCES2) { // SX2 requests contains additional data
				byRequestedVersion = data.ReadUInt8();
				byRequestedOptions = data.ReadUInt16();
			}
			//Although this shouldn't happen, it's just in case to any Mods that mess with version numbers.
			if (byRequestedVersion > 0 || client->GetSourceExchange1Version() > 1) {
				if (size < 16)
					throw GetResString(IDS_ERR_BADSIZE);

				if (thePrefs.GetDebugSourceExchange())
					AddDebugLogLine(false, _T("SXRecv: Client source request; %s, %s"), (LPCTSTR)client->DbgGetClientInfo(), (LPCTSTR)DbgGetFileInfo(packet));

				//first check shared file list, then download list
				uchar ucHash[MDX_DIGEST_SIZE];
				data.ReadHash16(ucHash);
				CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(ucHash);
				if (!reqfile)
					reqfile = theApp.downloadqueue->GetFileByID(ucHash);
				if (reqfile) {
					// There are some clients which do not follow the correct protocol sequence
					// of sending OP_REQUESTFILENAME, OP_SETREQFILEID, OP_REQUESTSOURCES. Those clients
					// will not get the best set of sources we could offer if they followed
					// the above noted protocol sequence. They better do it the right way
					// or they will get a random set of sources because we do not know their download
					// part status which may get cleared with the call of 'SetUploadFileID'.
					client->SetUploadFileID(reqfile);

					DWORD dwTimePassed = ::GetTickCount() - client->GetLastSrcReqTime() + CONNECTION_LATENCY;
					bool bNeverAskedBefore = (client->GetLastSrcReqTime() == 0);
					if ( //if not complete and file is rare
						(reqfile->IsPartFile()
							&& (bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS)
							&& static_cast<CPartFile*>(reqfile)->GetSourceCount() <= RARE_FILE
						)
							//OR if file is not rare or is complete
						|| bNeverAskedBefore || dwTimePassed > SOURCECLIENTREASKS * MINCOMMONPENALTY
					   )
					{
						client->SetLastSrcReqTime();
						Packet *tosend = reqfile->CreateSrcInfoPacket(client, byRequestedVersion, byRequestedOptions);
						if (tosend) {
							if (thePrefs.GetDebugClientTCPLevel() > 0)
								DebugSend("OP_AnswerSources", client, reqfile->GetFileHash());
							theStats.AddUpDataOverheadSourceExchange(tosend->size);
							SendPacket(tosend, true);
						}
					}
				} else
					client->CheckFailedFileIdReqs(ucHash);
			}
		}
		return;
	case OP_ANSWERSOURCES2:
	case OP_ANSWERSOURCES:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv(opcode == OP_ANSWERSOURCES2 ? "OP_AnswerSources2" : "OP_AnswerSources", client, (size >= (opcode == OP_ANSWERSOURCES2 ? 17u : 16u)) ? packet : NULL);
			theStats.AddDownDataOverheadSourceExchange(uRawSize);
			//client->CheckHandshakeFinished();

			CSafeMemFile data(packet, size);
			uint8 byVersion = (opcode == OP_ANSWERSOURCES2) ? data.ReadUInt8() : client->GetSourceExchange1Version();
			uchar hash[MDX_DIGEST_SIZE];
			data.ReadHash16(hash);
			CKnownFile *file = theApp.downloadqueue->GetFileByID(hash);
			if (file == NULL)
				client->CheckFailedFileIdReqs(hash);
			else if (file->IsPartFile()) {
				//set the client's answer time
				client->SetLastSrcAnswerTime();
				//and set the file's last answer time
				static_cast<CPartFile*>(file)->SetLastAnsweredTime();
				static_cast<CPartFile*>(file)->AddClientSources(&data, byVersion, (opcode == OP_ANSWERSOURCES2), client);
			}
		}
		return;
	case OP_FILEDESC:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_FileDesc", client);
		theStats.AddDownDataOverheadFileRequest(uRawSize);
		//client->CheckHandshakeFinished();

		client->ProcessMuleCommentPacket(packet, size);
		return;
	case OP_REQUESTPREVIEW:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_RequestPreView", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadOther(uRawSize);
		//client->CheckHandshakeFinished();

		if (thePrefs.CanSeeShares() == vsfaEverybody || (thePrefs.CanSeeShares() == vsfaFriends && client->IsFriend())) {
			if (thePrefs.GetVerbose())
				AddDebugLogLine(true, _T("Client '%s' (%s) requested Preview - accepted"), client->GetUserName(), (LPCTSTR)ipstr(client->GetConnectIP()));
			client->ProcessPreviewReq(packet, size);
		} else {
			// we don't send any answer here, because the client should know that he was not allowed to ask
			if (thePrefs.GetVerbose())
				AddDebugLogLine(true, _T("Client '%s' (%s) requested Preview - denied"), client->GetUserName(), (LPCTSTR)ipstr(client->GetConnectIP()));
		}
		return;
	case OP_PREVIEWANSWER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_PreviewAnswer", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadOther(uRawSize);
		//client->CheckHandshakeFinished();

		client->ProcessPreviewAnswer(packet, size);
		return;
	case OP_PEERCACHE_QUERY:
	case OP_PEERCACHE_ANSWER:
	case OP_PEERCACHE_ACK:
		theStats.AddDownDataOverheadFileRequest(uRawSize);
		return;
	case OP_PUBLICIP_ANSWER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_PublicIPAns", client);
		theStats.AddDownDataOverheadOther(uRawSize);

		client->ProcessPublicIPAnswer(packet, size);
		return;
	case OP_PUBLICIP_REQ:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_PublicIPReq", client);
			theStats.AddDownDataOverheadOther(uRawSize);

			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugSend("OP_PublicIPAns", client);
			Packet *pPacket = new Packet(OP_PUBLICIP_ANSWER, 4, OP_EMULEPROT);
			PokeUInt32(pPacket->pBuffer, client->GetIP());
			theStats.AddUpDataOverheadOther(pPacket->size);
			SendPacket(pPacket);
		}
		return;
	case OP_PORTTEST:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_PortTest", client);
			theStats.AddDownDataOverheadOther(uRawSize);

			m_bPortTestCon = true;
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugSend("OP_PortTest", client);
			Packet *replypacket = new Packet(OP_PORTTEST, 1);
			replypacket->pBuffer[0] = 0x12;
			theStats.AddUpDataOverheadOther(replypacket->size);
			SendPacket(replypacket);
		}
		return;
	case OP_CALLBACK:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_Callback", client);
			theStats.AddDownDataOverheadFileRequest(uRawSize);

			if (!Kademlia::CKademlia::IsRunning())
				return;
			CSafeMemFile data(packet, size);
			Kademlia::CUInt128 check;
			data.ReadUInt128(check);
			check.Xor(Kademlia::CUInt128(true));
			if (check == Kademlia::CKademlia::GetPrefs()->GetKadID()) {
				Kademlia::CUInt128 fileid;
				data.ReadUInt128(fileid);
				uchar fileid2[MDX_DIGEST_SIZE];
				fileid.ToByteArray(fileid2);
				if (theApp.sharedfiles->GetFileByID(fileid2) == NULL)
					if (theApp.downloadqueue->GetFileByID(fileid2) == NULL) {
						client->CheckFailedFileIdReqs(fileid2);
						return;
					}

				uint32 ip = data.ReadUInt32();
				uint16 tcp = data.ReadUInt16();
				CUpDownClient *callback = theApp.clientlist->FindClientByConnIP(ntohl(ip), tcp);
				if (callback == NULL) {
					callback = new CUpDownClient(NULL, tcp, ip, 0, 0);
					theApp.clientlist->AddClient(callback);
				}

				callback->TryToConnect(true);
			}
		}
		return;
	case OP_BUDDYPING:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_BuddyPing", client);
			theStats.AddDownDataOverheadOther(uRawSize);

			CUpDownClient *buddy = theApp.clientlist->GetBuddy();
			//Check that ping was from our buddy, has version, and not too soon;
			//ignore otherwise
			if (buddy == client && client->GetKadVersion() && client->AllowIncomingBuddyPingPong()) {
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_BuddyPong", client);
				Packet *replypacket = new Packet(OP_BUDDYPONG, 0, OP_EMULEPROT);
				theStats.AddDownDataOverheadOther(replypacket->size);
				SendPacket(replypacket);
				client->SetLastBuddyPingPongTime();
			}
		}
		return;
	case OP_BUDDYPONG:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_BuddyPong", client);
			theStats.AddDownDataOverheadOther(uRawSize);
			CUpDownClient *buddy = theApp.clientlist->GetBuddy();
			//Ignore pong not from our buddy or wrong version.
			if (buddy == client && client->GetKadVersion())
				client->SetLastBuddyPingPongTime();	//reset our socket timeout.
		}
		return;
	case OP_REASKCALLBACKTCP:
		{
			theStats.AddDownDataOverheadFileRequest(uRawSize);
			CUpDownClient *buddy = theApp.clientlist->GetBuddy();
			if (buddy != client) {
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugRecv("OP_ReaskCallbackTCP", client, NULL);
				//This callback was not from our buddy. Ignore.
				return;
			}
			CSafeMemFile data_in(packet, size);
			uint32 destip = data_in.ReadUInt32();
			uint16 destport = data_in.ReadUInt16();
			uchar reqfilehash[MDX_DIGEST_SIZE];
			data_in.ReadHash16(reqfilehash);
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_ReaskCallbackTCP", client, reqfilehash);
			CKnownFile *reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);

			bool bSenderMultipleIpUnknown = false;
			CUpDownClient *sender = theApp.uploadqueue->GetWaitingClientByIP_UDP(destip, destport, true, &bSenderMultipleIpUnknown);
			if (!reqfile) {
				if (thePrefs.GetDebugClientUDPLevel() > 0)
					DebugSend("OP_FileNotFound", NULL);
				Packet *response = new Packet(OP_FILENOTFOUND, 0, OP_EMULEPROT);
				theStats.AddUpDataOverheadFileRequest(response->size);
				if (sender)
					theApp.clientudp->SendPacket(response, destip, destport, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
				else
					theApp.clientudp->SendPacket(response, destip, destport, false, NULL, false, 0);
				return;
			}

			if (sender) {
				//Make sure we are still thinking about the same file
				if (md4equ(reqfilehash, sender->GetUploadFileID())) {
					sender->IncrementAskedCount();
					sender->SetLastUpRequest();
					//I messed up when I first added extended info to UDP
					//I should have originally used the entire ProcessExtenedInfo the first time.
					//So now I am forced to check UDPVersion to see if we are sending all the extended info.
					//For now on, we should not have to change anything here if we change
					//anything to the extended info data as this will be taken care of in ProcessExtendedInfo()
					//Update extended info.
					if (sender->GetUDPVersion() > 3)
						sender->ProcessExtendedInfo(data_in, reqfile);
						//Update our complete source counts.
					else if (sender->GetUDPVersion() > 2) {
						uint16 nCompleteCountLast = sender->GetUpCompleteSourcesCount();
						uint16 nCompleteCountNew = data_in.ReadUInt16();
						sender->SetUpCompleteSourcesCount(nCompleteCountNew);
						if (nCompleteCountLast != nCompleteCountNew)
							reqfile->UpdatePartsInfo();
					}
					CSafeMemFile data_out(128);
					if (sender->GetUDPVersion() > 3)
						if (reqfile->IsPartFile())
							static_cast<CPartFile*>(reqfile)->WritePartStatus(data_out);
						else
							data_out.WriteUInt16(0);

					data_out.WriteUInt16((uint16)theApp.uploadqueue->GetWaitingPosition(sender));
					if (thePrefs.GetDebugClientUDPLevel() > 0)
						DebugSend("OP_ReaskAck", sender);
					Packet *response = new Packet(data_out, OP_EMULEPROT);
					response->opcode = OP_REASKACK;
					theStats.AddUpDataOverheadFileRequest(response->size);
					theApp.clientudp->SendPacket(response, destip, destport, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
				} else {
					DebugLogWarning(_T("Client UDP socket; OP_REASKCALLBACKTCP; reqfile does not match"));
					TRACE(_T("reqfile:         %s\n"), (LPCTSTR)DbgGetFileInfo(reqfile->GetFileHash()));
					TRACE(_T("sender->GetRequestFile(): %s\n"), sender->GetRequestFile() ? (LPCTSTR)DbgGetFileInfo(sender->GetRequestFile()->GetFileHash()) : _T("(null)"));
				}
			} else {
				if (!bSenderMultipleIpUnknown) {
					if (theApp.uploadqueue->GetWaitingUserCount() + 50 > thePrefs.GetQueueSize()) {
						if (thePrefs.GetDebugClientUDPLevel() > 0)
							DebugSend("OP_QueueFull", NULL);
						Packet *response = new Packet(OP_QUEUEFULL, 0, OP_EMULEPROT);
						theStats.AddUpDataOverheadFileRequest(response->size);
						theApp.clientudp->SendPacket(response, destip, destport, false, NULL, false, 0);
					}
				} else
					DebugLogWarning(_T("OP_REASKCALLBACKTCP Packet received - multiple clients with the same IP but different UDP port found. Possible UDP Port mapping problem, enforcing TCP connection. IP: %s, Port: %u"), (LPCTSTR)ipstr(destip), destport);
			}
		}
		return;
	case OP_AICHANSWER:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_AichAnswer", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(uRawSize);

		client->ProcessAICHAnswer(packet, size);
		return;
	case OP_AICHREQUEST:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_AichRequest", client, (size >= 16) ? packet : NULL);
		theStats.AddDownDataOverheadFileRequest(uRawSize);

		client->ProcessAICHRequest(packet, size);
		return;
	case OP_AICHFILEHASHANS:
		{
			// those should not be received normally, since we should only get those in MULTIPACKET
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AichFileHashAns", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(uRawSize);

			CSafeMemFile data(packet, size);
			client->ProcessAICHFileHash(&data, NULL, NULL);
		}
		return;
	case OP_AICHFILEHASHREQ:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_AichFileHashReq", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(uRawSize);

			// those should not be received normally, since we should only get those in MULTIPACKET
			CSafeMemFile data(packet, size);
			uchar abyHash[MDX_DIGEST_SIZE];
			data.ReadHash16(abyHash);
			CKnownFile *pPartFile = theApp.sharedfiles->GetFileByID(abyHash);
			if (pPartFile == NULL)
				client->CheckFailedFileIdReqs(abyHash);
			else if (client->IsSupportingAICH() && pPartFile->GetFileIdentifier().HasAICHHash()) {
				if (thePrefs.GetDebugClientTCPLevel() > 0)
					DebugSend("OP_AichFileHashAns", client, abyHash);
				CSafeMemFile data_out;
				data_out.WriteHash16(abyHash);
				pPartFile->GetFileIdentifier().GetAICHHash().Write(data_out);
				Packet *response = new Packet(data_out, OP_EMULEPROT, OP_AICHFILEHASHANS);
				theStats.AddUpDataOverheadFileRequest(response->size);
				SendPacket(response);
			}
		}
		return;
	case OP_REQUESTPARTS_I64:
		{
			// see also OP_REQUESTPARTS
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_RequestParts_I64", client, (size >= 16) ? packet : NULL);
			theStats.AddDownDataOverheadFileRequest(size);

			CSafeMemFile data(packet, size);
			uchar reqfilehash[MDX_DIGEST_SIZE];
			data.ReadHash16(reqfilehash);

			uint64 aOffset[3 * 2]; //3 starts, then 3 ends
			for (unsigned i = 0; i < 3 * 2; ++i)
				aOffset[i] = data.ReadUInt64();
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				for (unsigned i = 0; i < 3; ++i)
					Debug(_T("  Start[%u]=%I64u  End[%u]=%I64u  Size=%I64u\n"), i, aOffset[i], i, aOffset[i + 3], aOffset[i + 3] - aOffset[i]);

			for (unsigned i = 0; i < 3; ++i)
				if (aOffset[i] < aOffset[i + 3]) {
					Requested_Block_Struct *reqblock = new Requested_Block_Struct;
					reqblock->StartOffset = aOffset[i];
					reqblock->EndOffset = aOffset[i + 3];
					md4cpy(reqblock->FileID, reqfilehash);
					reqblock->transferred = 0;
					client->AddReqBlock(reqblock, false);
				} else if (thePrefs.GetVerbose() && (aOffset[i + 3] != 0 || aOffset[i] != 0))
					DebugLogWarning(_T("Client requests invalid %u. file block %I64u-%I64u (%I64d bytes): %s"), i, aOffset[i], aOffset[i + 3], aOffset[i + 3] - aOffset[i], (LPCTSTR)client->DbgGetClientInfo());

				client->AddReqBlock(NULL, true);
		}
		return;
	case OP_COMPRESSEDPART:
	case OP_SENDINGPART_I64:
	case OP_COMPRESSEDPART_I64:
		{
			// see also OP_SENDINGPART
			if (thePrefs.GetDebugClientTCPLevel() > 1) {
				LPCSTR sOp;
				switch (opcode) {
				case OP_COMPRESSEDPART:
					sOp = "OP_CompressedPart";
					break;
				case OP_SENDINGPART_I64:
					sOp = "OP_SendingPart_I64";
					break;
				default: //OP_COMPRESSEDPART_I64
					sOp = "OP_CompressedPart_I64";
				}
				DebugRecv(sOp, client, (size >= 16) ? packet : NULL);
			}

			bool bCompress = (opcode != OP_SENDINGPART_I64);
			bool b64 = (opcode != OP_COMPRESSEDPART);
			theStats.AddDownDataOverheadFileRequest(16 + (b64 ? 8 : 4) + (bCompress ? 4 : 8));
			//client->CheckHandshakeFinished();
			EDownloadState newDS = DS_NONE;
			const CPartFile *creqfile = client->GetRequestFile();
			if (creqfile && !creqfile->IsStopped() && inSet(creqfile->GetStatus(), PS_READY, PS_EMPTY)) {
				client->ProcessBlockPacket(packet, size, bCompress, b64);
				if (!creqfile->IsStopped() && creqfile->GetStatus() == PS_ERROR)
					newDS = DS_ONQUEUE;
				else
					newDS = DS_CONNECTED; //any state but DS_NONE or DS_ONQUEUE
			}
			if (newDS != DS_CONNECTED && client) { //client could have been deleted while debugging
				client->SendCancelTransfer();
				client->SetDownloadState(newDS);
			}
		}
		return;
	case OP_CHATCAPTCHAREQ:
		{
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_CHATCAPTCHAREQ", client);
			theStats.AddDownDataOverheadOther(uRawSize);
			CSafeMemFile data(packet, size);
			client->ProcessCaptchaRequest(data);
		}
		return;
	case OP_CHATCAPTCHARES:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_CHATCAPTCHARES", client);
		theStats.AddDownDataOverheadOther(uRawSize);
		if (size < 1)
			throw GetResString(IDS_ERR_BADSIZE);
		client->ProcessCaptchaReqRes(packet[0]);
		return;
	case OP_FWCHECKUDPREQ: //*Support required for Kad version >= 6
		{
			// Kad related packet
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugRecv("OP_FWCHECKUDPREQ", client);
			theStats.AddDownDataOverheadOther(uRawSize);
			CSafeMemFile data(packet, size);
			client->ProcessFirewallCheckUDPRequest(data);
		}
		return;
	case OP_KAD_FWTCPCHECK_ACK: //*Support required for Kad version >= 7
		// Kad related packet, replaces KADEMLIA_FIREWALLED_ACK_RES
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_KAD_FWTCPCHECK_ACK", client);
		if (theApp.clientlist->IsKadFirewallCheckIP(client->GetIP())) {
			if (Kademlia::CKademlia::IsRunning())
				Kademlia::CKademlia::GetPrefs()->IncFirewalled();
		} else
			DebugLogWarning(_T("Unrequested OP_KAD_FWTCPCHECK_ACK packet from client %s"), (LPCTSTR)client->DbgGetClientInfo());
		return;
	case OP_HASHSETREQUEST2:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_HashSetReq2", client);
		theStats.AddDownDataOverheadFileRequest(size);
		client->SendHashsetPacket(packet, size, true);
		return;
	case OP_HASHSETANSWER2:
		if (thePrefs.GetDebugClientTCPLevel() > 0)
			DebugRecv("OP_HashSetAnswer2", client);
		theStats.AddDownDataOverheadFileRequest(size);
		client->ProcessHashSet(packet, size, true);
		return;
	default:
		theStats.AddDownDataOverheadOther(uRawSize);
		PacketToDebugLogLine(_T("eMule"), packet, size, opcode);
	}
}

void CClientReqSocket::PacketToDebugLogLine(LPCTSTR protocol, const uchar *packet, uint32 size, UINT opcode)
{
	if (thePrefs.GetVerbose()) {
		CString buffer;
		buffer.Format(_T("Unknown %s protocol Opcode=0x%02x, %s"), protocol, opcode, (LPCTSTR)DbgGetHexDump(packet, size));
		DbgAppendClientInfo(buffer);
		DebugLogWarning(_T("%s"), (LPCTSTR)buffer);
	}
}

CString CClientReqSocket::DbgGetClientInfo()
{
	SOCKADDR_IN sockAddr = {};
	int nSockAddrLen = sizeof sockAddr;
	GetPeerName((LPSOCKADDR)&sockAddr, &nSockAddrLen);
	CString str;
	if (sockAddr.sin_addr.s_addr != 0 && (client == NULL || sockAddr.sin_addr.s_addr != client->GetIP()))
		str.Format(_T("IP=%s"), (LPCTSTR)ipstr(sockAddr.sin_addr));
	if (client)
		str.AppendFormat(&_T("; Client=%s")[str.IsEmpty() ? 2 : 0], (LPCTSTR)client->DbgGetClientInfo());
	return str;
}

void CClientReqSocket::DbgAppendClientInfo(CString &str)
{
	CString strClientInfo(DbgGetClientInfo());
	if (!strClientInfo.IsEmpty())
		str.AppendFormat(&_T("; %s")[str.IsEmpty() ? 2 : 0], (LPCTSTR)strClientInfo);
}

void CClientReqSocket::OnConnect(int nErrorCode)
{
	SetConState(SS_Complete);
	CEMSocket::OnConnect(nErrorCode);
	if (nErrorCode) {
		if (thePrefs.GetVerbose()) {
			const CString &strTCPError(GetFullErrorMessage(nErrorCode));
			if ((nErrorCode != WSAECONNREFUSED && nErrorCode != WSAETIMEDOUT) || !GetLastProxyError().IsEmpty())
				DebugLogError(_T("Client TCP socket (OnConnect): %s; %s"), (LPCTSTR)strTCPError, (LPCTSTR)DbgGetClientInfo());
			Disconnect(strTCPError);
		} else
			Disconnect(_T(""));
	} else
		//This socket may have been delayed by SP2 protection, lets make sure it doesn't time out instantly.
		ResetTimeOutTimer();
}

void CClientReqSocket::OnSend(int nErrorCode)
{
	ResetTimeOutTimer();
	CEMSocket::OnSend(nErrorCode);
}

void CClientReqSocket::OnError(int nErrorCode)
{
	CString strTCPError;
	if (thePrefs.GetVerbose()) {
		if (nErrorCode == ERR_WRONGHEADER)
			strTCPError = _T("Error: Wrong header");
		else if (nErrorCode == ERR_TOOBIG)
			strTCPError = _T("Error: Too much data sent");
		else if (nErrorCode == ERR_ENCRYPTION)
			strTCPError = _T("Error: Encryption layer error");
		else if (nErrorCode == ERR_ENCRYPTION_NOTALLOWED)
			strTCPError = _T("Error: Unencrypted Connection when Encryption was required");
		else
			strTCPError = GetErrorMessage(nErrorCode);
		DebugLogWarning(_T("Client TCP socket: %s; %s"), (LPCTSTR)strTCPError, (LPCTSTR)DbgGetClientInfo());
	}
	Disconnect(strTCPError);
}

bool CClientReqSocket::PacketReceived(Packet *packet)
{
	CString *psErr;
	const UINT uRawSize = packet->size;
	const uint8 opcode = packet->opcode;
	bool bDelClient;
	try {
		try {
			switch (packet->prot) {
			case OP_EDONKEYPROT:
				if (client) {
					//if (opcode != OP_HELLO && opcode != OP_HELLOANSWER)
					//	client->CheckHandshakeFinished();
				} else if (opcode != OP_HELLO) {
					theStats.AddDownDataOverheadOther(packet->size);
					throw GetResString(IDS_ERR_NOHELLO);
				}

				ProcessPacket((BYTE*)packet->pBuffer, uRawSize, opcode);
				break;
			case OP_PACKEDPROT:
				if (!packet->UnPackPacket()) {
					if (thePrefs.GetVerbose())
						DebugLogError(_T("Failed to decompress client TCP packet; %s; %s"), (LPCTSTR)DbgGetClientTCPPacket(packet->prot, packet->opcode, packet->size), (LPCTSTR)DbgGetClientInfo());
					break;
				}
			case OP_EMULEPROT:
				if (opcode != OP_PORTTEST) {
					if (!client) {
						theStats.AddDownDataOverheadOther(uRawSize);
						throw GetResString(IDS_ERR_UNKNOWNCLIENTACTION);
					}
					if (thePrefs.m_iDbgHeap >= 2)
						ASSERT_VALID(client);
				}

				ProcessExtPacket((BYTE*)packet->pBuffer, packet->size, packet->opcode, uRawSize);
				break;
			default:
				theStats.AddDownDataOverheadOther(uRawSize);
				if (thePrefs.GetVerbose())
					DebugLogWarning(_T("Received unknown client TCP packet; %s; %s"), (LPCTSTR)DbgGetClientTCPPacket(packet->prot, packet->opcode, packet->size), (LPCTSTR)DbgGetClientInfo());

				if (client)
					client->SetDownloadState(DS_ERROR, _T("Unknown protocol"));
				Disconnect(_T("Unknown protocol"));
			}
		} catch (CFileException *ex) {
			ex->Delete();
			throw GetResString(IDS_ERR_INVALIDPACKET);
		} catch (CMemoryException *ex) {
			ex->Delete();
			throwCStr(_T("Memory exception"));
#ifndef _DEBUG
		} catch (...) {
			throwCStr(_T("Unknown exception"));
#endif
		}
		return true;
	} catch (CClientException *ex) { // similar to 'CString&' exception but client deletion is optional
		bDelClient = ex->m_bDelete;
		psErr = new CString(ex->m_strMsg);
		ex->Delete();
	} catch (const CString &ex) {
		bDelClient = true;
		psErr = new CString(ex);
	}
	//Error handling
	bool bIsDonkey = (packet->prot == OP_EDONKEYPROT);
	LPCTSTR sProtocol = bIsDonkey ? _T("eDonkey") : _T("eMule");
	if (thePrefs.GetVerbose())
		DebugLogWarning(_T("Error: '%s' while processing %s packet: opcode=%s  size=%u; %s")
			, (LPCTSTR)*psErr
			, sProtocol
			, (LPCTSTR)(bIsDonkey ? DbgGetDonkeyClientTCPOpcode(opcode) : DbgGetMuleClientTCPOpcode(opcode))
			, uRawSize
			, (LPCTSTR)DbgGetClientInfo());

	CString sErr2;
	sErr2.Format(_T("Error while processing %s packet:  %s"), (LPCTSTR)sProtocol, (LPCTSTR)*psErr);
	if (bDelClient && client)
		client->SetDownloadState(DS_ERROR, sErr2);
	Disconnect(sErr2);
	delete psErr;
	return false;
}

void CClientReqSocket::OnReceive(int nErrorCode)
{
	ResetTimeOutTimer();
	CEMSocket::OnReceive(nErrorCode);
}

bool CClientReqSocket::Create()
{
	theApp.listensocket->AddConnection();
	return CAsyncSocketEx::Create(0, SOCK_STREAM, FD_WRITE | FD_READ | FD_CLOSE | FD_CONNECT, thePrefs.GetBindAddr());
}

SocketSentBytes CClientReqSocket::SendControlData(uint32 maxNumberOfBytesToSend, uint32 overchargeMaxBytesToSend)
{
	SocketSentBytes returnStatus = CEMSocket::SendControlData(maxNumberOfBytesToSend, overchargeMaxBytesToSend);
	if (returnStatus.success && (returnStatus.sentBytesControlPackets > 0 || returnStatus.sentBytesStandardPackets > 0))
		ResetTimeOutTimer();
	return returnStatus;
}

SocketSentBytes CClientReqSocket::SendFileAndControlData(uint32 maxNumberOfBytesToSend, uint32 overchargeMaxBytesToSend)
{
	SocketSentBytes returnStatus = CEMSocket::SendFileAndControlData(maxNumberOfBytesToSend, overchargeMaxBytesToSend);
	if (returnStatus.success && (returnStatus.sentBytesControlPackets > 0 || returnStatus.sentBytesStandardPackets > 0))
		ResetTimeOutTimer();
	return returnStatus;
}

void CClientReqSocket::SendPacket(Packet *packet, bool controlpacket, uint32 actualPayloadSize, bool bForceImmediateSend)
{
	ResetTimeOutTimer();
	CEMSocket::SendPacket(packet, controlpacket, actualPayloadSize, bForceImmediateSend);
}

bool CListenSocket::SendPortTestReply(char result, bool disconnect)
{
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;) {
		CClientReqSocket *cur_sock = socket_list.GetNext(pos);
		if (cur_sock->m_bPortTestCon) {
			if (thePrefs.GetDebugClientTCPLevel() > 0)
				DebugSend("OP_PortTest", cur_sock->client);
			Packet *replypacket = new Packet(OP_PORTTEST, 1);
			replypacket->pBuffer[0] = result;
			theStats.AddUpDataOverheadOther(replypacket->size);
			cur_sock->SendPacket(replypacket);
			if (disconnect)
				cur_sock->m_bPortTestCon = false;
			return true;
		}
	}
	return false;
}

CListenSocket::CListenSocket()
	: bListening()
	, m_OpenSocketsInterval()
	, maxconnectionreached()
	, m_ConnectionStates()
	, m_nPendingConnections()
	, peakconnections()
	, totalconnectionchecks()
	, averageconnections()
	, activeconnections()
	, m_port()
	, m_nHalfOpen()
	, m_nComp()
{
}

CListenSocket::~CListenSocket()
{
	CListenSocket::Close();
	KillAllSockets();
}

bool CListenSocket::Rebind()
{
	if (thePrefs.GetPort() == m_port)
		return false;

	Close();
	KillAllSockets();

	return StartListening();
}

bool CListenSocket::StartListening()
{
	bListening = true;

	// Creating the socket with SO_REUSEADDR may solve LowID issues if emule was restarted
	// quickly or started after a crash, but(!) it will also create another problem. If the
	// socket is already used by some other application (e.g. a 2nd emule), we though bind
	// to that socket leading to the situation that 2 applications are listening on the same
	// port!
	if (!Create(thePrefs.GetPort(), SOCK_STREAM, FD_ACCEPT, thePrefs.GetBindAddr(), AF_INET))
		return false;

	// Rejecting a connection with conditional WSAAccept and not using SO_CONDITIONAL_ACCEPT
	// -------------------------------------------------------------------------------------
	// recv: SYN
	// send: SYN ACK (!)
	// recv: ACK
	// send: ACK RST
	// recv: PSH ACK + OP_HELLO packet
	// send: RST
	// --- 455 total bytes (depending on OP_HELLO packet)
	// In case SO_CONDITIONAL_ACCEPT is not used, the TCP/IP stack establishes the connection
	// before WSAAccept has a chance to reject it. That's why the remote peer starts to send
	// its first data packet.
	// ---
	// Not using SO_CONDITIONAL_ACCEPT gives us 6 TCP packets and the OP_HELLO data. We
	// have to lookup the IP only 1 time. This is still way less traffic than rejecting the
	// connection by closing it after the 'Accept'.

	// Rejecting a connection with conditional WSAAccept and using SO_CONDITIONAL_ACCEPT
	// ---------------------------------------------------------------------------------
	// recv: SYN
	// send: ACK RST
	// recv: SYN
	// send: ACK RST
	// recv: SYN
	// send: ACK RST
	// --- 348 total bytes
	// The TCP/IP stack tries to establish the connection 3 times until it gives up.
	// Furthermore the remote peer experiences a total timeout of ~ 1 minute which is
	// supposed to be the default TCP/IP connection timeout (as noted in MSDN).
	// ---
	// Although we get a total of 6 TCP packets in case of using SO_CONDITIONAL_ACCEPT,
	// it's still less than not using SO_CONDITIONAL_ACCEPT. But, we have to lookup
	// the IP 3 times instead of 1 time.

	//if (thePrefs.GetConditionalTCPAccept() && !thePrefs.GetProxySettings().bUseProxy) {
	//	int iOptVal = 1;
	//	VERIFY( SetSockOpt(SO_CONDITIONAL_ACCEPT, &iOptVal, sizeof iOptVal) );
	//}

	if (!Listen())
		return false;

	m_port = thePrefs.GetPort();
	return true;
}

void CListenSocket::ReStartListening()
{
	bListening = true;

	ASSERT(m_nPendingConnections >= 0);
	if (m_nPendingConnections > 0) {
		--m_nPendingConnections;
		OnAccept(0);
	}
}

void CListenSocket::StopListening()
{
	bListening = false;
	++maxconnectionreached;
}

static int s_iAcceptConnectionCondRejected;

int CALLBACK AcceptConnectionCond(LPWSABUF lpCallerId, LPWSABUF /*lpCallerData*/, LPQOS /*lpSQOS*/, LPQOS /*lpGQOS*/,
	LPWSABUF /*lpCalleeId*/, LPWSABUF /*lpCalleeData*/, GROUP FAR* /*g*/, DWORD_PTR /*dwCallbackData*/) noexcept
{
	if (lpCallerId && lpCallerId->buf && lpCallerId->len >= sizeof SOCKADDR_IN) {
		LPSOCKADDR_IN pSockAddr = (LPSOCKADDR_IN)lpCallerId->buf;
		ASSERT(pSockAddr->sin_addr.s_addr != 0 && pSockAddr->sin_addr.s_addr != INADDR_NONE);

		if (theApp.ipfilter->IsFiltered(pSockAddr->sin_addr.s_addr)) {
			if (thePrefs.GetLogFilteredIPs())
				AddDebugLogLine(false, _T("Rejecting connection attempt (IP=%s) - IP filter (%s)"), (LPCTSTR)ipstr(pSockAddr->sin_addr.s_addr), (LPCTSTR)theApp.ipfilter->GetLastHit());
			s_iAcceptConnectionCondRejected = 1;
			return CF_REJECT;
		}

		if (theApp.clientlist->IsBannedClient(pSockAddr->sin_addr.s_addr)) {
			if (thePrefs.GetLogBannedClients()) {
				CUpDownClient *pClient = theApp.clientlist->FindClientByIP(pSockAddr->sin_addr.s_addr);
				if (pClient != NULL)
					AddDebugLogLine(false, _T("Rejecting connection attempt of banned client %s %s"), (LPCTSTR)ipstr(pSockAddr->sin_addr.s_addr), (LPCTSTR)pClient->DbgGetClientInfo());
			}
			s_iAcceptConnectionCondRejected = 2;
			return CF_REJECT;
		}
	} else if (thePrefs.GetVerbose())
		DebugLogError(_T("Client TCP socket: AcceptConnectionCond unexpected lpCallerId"));

	return CF_ACCEPT;
}

void CListenSocket::OnAccept(int nErrorCode)
{
	if (!nErrorCode) {
		if (++m_nPendingConnections < 1) {
			ASSERT(0);
			m_nPendingConnections = 1;
		}

		if (TooManySockets(true) && !theApp.serverconnect->IsConnecting()) {
			StopListening();
			return;
		}
		if (!bListening)
			ReStartListening(); //If the client is still at maxconnections, this will allow it to go above it. But if you don't, you will get a low ID on all servers.

		uint32 nFataErrors = 0;
		while (m_nPendingConnections > 0) {
			--m_nPendingConnections;

			CClientReqSocket *newclient;
			SOCKADDR_IN SockAddr = {};
			int iSockAddrLen = sizeof SockAddr;
			if (thePrefs.GetConditionalTCPAccept() && !thePrefs.GetProxySettings().bUseProxy) {
				s_iAcceptConnectionCondRejected = 0;
				SOCKET sNew = WSAAccept(m_SocketData.hSocket, (LPSOCKADDR)&SockAddr, &iSockAddrLen, AcceptConnectionCond, 0);
				if (sNew == INVALID_SOCKET) {
					DWORD nError = CAsyncSocket::GetLastError();
					if (nError == WSAEWOULDBLOCK) {
						DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says WSAEWOULDBLOCK - setting counter to zero!"), __FUNCTION__, m_nPendingConnections);
						m_nPendingConnections = 0;
						break;
					}

					if (nError != WSAECONNREFUSED || s_iAcceptConnectionCondRejected == 0) {
						DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says %s - setting counter to zero!"), __FUNCTION__, m_nPendingConnections, (LPCTSTR)GetErrorMessage(nError, 1));
						if (++nFataErrors > 10) {
							// the question is what todo on an error. We can't just ignore it because then the backlog will fill up
							// and lock everything. We cannot also just endlessly try to repeat it because this will lock up eMule
							// this should basically never happen anyway
							// however if we are in such position, try to reinitialize the socket.
							DebugLogError(LOG_STATUSBAR, _T("%hs: Accept() Error Loop, recreating socket"), __FUNCTION__);
							Close();
							StartListening();
							m_nPendingConnections = 0;
							break;
						}
					} else if (s_iAcceptConnectionCondRejected == 1)
						++theStats.filteredclients;

					continue;
				}
				newclient = new CClientReqSocket;
				VERIFY(newclient->InitAsyncSocketExInstance());
				newclient->m_SocketData.hSocket = sNew;
				newclient->AttachHandle();

				AddConnection();
			} else {
				newclient = new CClientReqSocket;
				if (!Accept(*newclient, (LPSOCKADDR)&SockAddr, &iSockAddrLen)) {
					newclient->Safe_Delete();
					DWORD nError = CAsyncSocket::GetLastError();
					if (nError == WSAEWOULDBLOCK) {
						DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says WSAEWOULDBLOCK - setting counter to zero!"), __FUNCTION__, m_nPendingConnections);
						m_nPendingConnections = 0;
						break;
					}
					DebugLogError(LOG_STATUSBAR, _T("%hs: Backlog counter says %u connections waiting, Accept() says %s - setting counter to zero!"), __FUNCTION__, m_nPendingConnections, (LPCTSTR)GetErrorMessage(nError, 1));
					if (++nFataErrors > 10) {
						// the question is what to do on an error. We can't just ignore it because then the backlog will fill up
						// and lock everything. We cannot also just endlessly try to repeat it because this will lock up eMule
						// this should basically never happen anyway
						// however if we are in such a position, try to reinitialize the socket.
						DebugLogError(LOG_STATUSBAR, _T("%hs: Accept() Error Loop, recreating socket"), __FUNCTION__);
						Close();
						StartListening();
						m_nPendingConnections = 0;
						break;
					}
					continue;
				}

				AddConnection();

				if (SockAddr.sin_addr.s_addr == INADDR_ANY) { // for safety.
					iSockAddrLen = (int)sizeof SockAddr;
					newclient->GetPeerName((LPSOCKADDR)&SockAddr, &iSockAddrLen);
					DebugLogWarning(_T("SockAddr.sin_addr.s_addr == 0;  GetPeerName returned %s"), (LPCTSTR)ipstr(SockAddr.sin_addr.s_addr));
				}

				ASSERT(SockAddr.sin_addr.s_addr != INADDR_ANY && SockAddr.sin_addr.s_addr != INADDR_NONE);

				if (theApp.ipfilter->IsFiltered(SockAddr.sin_addr.s_addr)) {
					if (thePrefs.GetLogFilteredIPs())
						AddDebugLogLine(false, _T("Rejecting connection attempt (IP=%s) - IP filter (%s)"), (LPCTSTR)ipstr(SockAddr.sin_addr.s_addr), (LPCTSTR)theApp.ipfilter->GetLastHit());
					newclient->Safe_Delete();
					++theStats.filteredclients;
					continue;
				}

				if (theApp.clientlist->IsBannedClient(SockAddr.sin_addr.s_addr)) {
					if (thePrefs.GetLogBannedClients()) {
						CUpDownClient *pClient = theApp.clientlist->FindClientByIP(SockAddr.sin_addr.s_addr);
						if (pClient)
							AddDebugLogLine(false, _T("Rejecting connection attempt of banned client %s %s"), (LPCTSTR)ipstr(SockAddr.sin_addr.s_addr), (LPCTSTR)pClient->DbgGetClientInfo());
					}
					newclient->Safe_Delete();
					continue;
				}
			}
			newclient->AsyncSelect(FD_WRITE | FD_READ | FD_CLOSE);
		}

		ASSERT(m_nPendingConnections >= 0);
	}
}

void CListenSocket::Process()
{
	m_OpenSocketsInterval = 0;
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;) {
		CClientReqSocket *cur_sock = socket_list.GetNext(pos);
		if (cur_sock->deletethis) {
			if (cur_sock->m_SocketData.hSocket != INVALID_SOCKET)
				cur_sock->Close();			// calls 'closesocket'
			else
				cur_sock->Delete_Timed();	// may delete 'cur_sock'
		} else
			cur_sock->CheckTimeOut();		// may call 'shutdown'
	}

	if ((GetOpenSockets() + 5 < thePrefs.GetMaxConnections() || theApp.serverconnect->IsConnecting()) && !bListening)
		ReStartListening();
}

void CListenSocket::RecalculateStats()
{
	memset(m_ConnectionStates, 0, sizeof m_ConnectionStates);
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;)
		switch (socket_list.GetNext(pos)->GetConState()) {
		case EMS_DISCONNECTED:
			++m_ConnectionStates[0];
			break;
		case EMS_NOTCONNECTED:
			++m_ConnectionStates[1];
			break;
		case EMS_CONNECTED:
			++m_ConnectionStates[2];
		}
}

void CListenSocket::AddSocket(CClientReqSocket *toadd)
{
	socket_list.AddTail(toadd);
}

void CListenSocket::RemoveSocket(CClientReqSocket *todel)
{
	POSITION pos = socket_list.Find(todel);
	if (pos != NULL)
		socket_list.RemoveAt(pos);
}

void CListenSocket::KillAllSockets()
{
	while (!socket_list.IsEmpty()) {
		const CClientReqSocket *cur_socket = socket_list.GetHead();
		if (cur_socket->client)
			delete cur_socket->client;
		else
			delete cur_socket;
	}
}

bool CListenSocket::TooManySockets(bool bIgnoreInterval)
{
	return GetOpenSockets() > thePrefs.GetMaxConnections()
		|| (m_OpenSocketsInterval > thePrefs.GetMaxConperFive() * GetMaxConperFiveModifier() && !bIgnoreInterval)
		|| (m_nHalfOpen >= thePrefs.GetMaxHalfConnections() && !bIgnoreInterval);
}

bool CListenSocket::IsValidSocket(CClientReqSocket *totest)
{
	return socket_list.Find(totest) != NULL;
}

#ifdef _DEBUG
void CListenSocket::Debug_ClientDeleted(CUpDownClient *deleted)
{
	for (POSITION pos = socket_list.GetHeadPosition(); pos != NULL;) {
		CClientReqSocket *cur_sock = socket_list.GetNext(pos);
		if (!cur_sock)
			AfxDebugBreak();
		if (thePrefs.m_iDbgHeap >= 2)
			ASSERT_VALID(cur_sock);
		if (cur_sock->client == deleted)
			AfxDebugBreak();
	}
}
#endif

void CListenSocket::UpdateConnectionsStatus()
{
	activeconnections = GetOpenSockets();

	// Update statistics for 'peak connections'
	if (peakconnections < activeconnections)
		peakconnections = activeconnections;
	if (peakconnections > thePrefs.GetConnPeakConnections())
		thePrefs.SetConnPeakConnections(peakconnections);

	if (theApp.IsConnected()) {
		if (++totalconnectionchecks == 0)
			 // wrap around occurred, avoid division by zero
			totalconnectionchecks = 100;

		// Get a weight for the 'avg. connections' value. The longer we run the higher
		// gets the weight (the percent of 'avg. connections' we use).
		float fPercent = (totalconnectionchecks - 1) / (float)totalconnectionchecks;
		if (fPercent > 0.99f)
			fPercent = 0.99f;

		// The longer we run the more we use the 'avg. connections' value and the less we
		// use the 'active connections' value. However, if we are running quite some time
		// without any connections (except the server connection) we will eventually create
		// a floating point underflow exception.
		averageconnections = averageconnections * fPercent + activeconnections * (1.0f - fPercent);
		if (averageconnections < 0.001f)
			averageconnections = 0.001f;	// avoid floating point underflow
	}
}

float CListenSocket::GetMaxConperFiveModifier()
{
	float SpikeSize = max(1.0f, GetOpenSockets() - averageconnections);
	float SpikeTolerance = 25.0f * thePrefs.GetMaxConperFive() / 10.0f;

	return (SpikeSize > SpikeTolerance) ? 0.0f : 1.0f - SpikeSize / SpikeTolerance;
}

CAsyncSocketEx* CListenSocket::OnAcceptEx(int /*nErrorCode*/)
{
	return new CClientReqSocket();
}
