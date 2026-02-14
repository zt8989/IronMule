/*
 * $Id: TraverseBySourceExchange.cpp 11398 2009-03-17 11:00:27Z huby $
 * 
 * this file is part of easyMule
 * Copyright (C)2002-2008 VeryCD Dev Team ( strEmail.Format("%s@%s", "emuledev", "verycd.com") / http: * www.easymule.org )
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include "StdAfx.h"
#include ".\traversebysourceexchange.h"

#include "../emule.h"
#include "NatThread.h"
#include "NatSocket.h"
#include "ClientList.h"
#include "updownclient.h"
#include "ListenSocket.h"
#include "ServerConnect.h"
#include "otherfunctions.h"

#ifdef _DEBUG_NAT
	extern void T_TRACE(char* fmt, ...);
#else
	#define T_TRACE
#endif

CTraverseBySourceExchange::CTraverseBySourceExchange(const uchar * uh, CTraverseStrategy * pNext)
: CTraverseStrategy(uh, pNext)
{
	m_dwTraverseIp  = 0;
	m_wTraversePort = 0;

	m_Sock = NULL;

	m_SendPingTime   = m_SendReqTime = m_SendConnAckTime = 0;
	m_nSendReqCount  = 0;
	m_nSendPingCount = 0;
	m_nPassivePing   = 0;

	m_bAcceptor      = false;
	m_dwClientIp     = 0;
	m_wClientPort    = 0;

	m_dwState         = 0;
	m_nSendConnAck    = 0;
	m_dwConnAskNumber = GetTickCount();

	m_dwNextSyncInterval = SYNC_INIT_ATTEMPT_INTERVAL;
}

CTraverseBySourceExchange::~CTraverseBySourceExchange(void)
{
}

void CTraverseBySourceExchange::SendPacket()
{
	m_bFailed = m_dwState & NAT_E_NOPEER;

	try
	{
		if(!m_bFailed && (m_dwState&NAT_S_SYNC)==0 && time(NULL)-m_SendReqTime > m_dwNextSyncInterval) //  5 seconds
		{
			//  failed to connect
			if(m_nSendReqCount > SYNC_ATTEMPT_TIMES)
			{
				m_dwState|=NAT_E_TIMEOUT;
				Failed();
			}
			else
			{
				if(m_nSendReqCount==0)
					_AddLogLine(false, _T("Begin to connect %s."), UserHashToString(m_UserHash));
				SendConnectReq();
			}
		}

		if(m_bFailed)
		{
			if(m_Sock)// && pClientSock->client)
			{
				//m_Sock->m_bUseNat = false;
			}

			if(m_dwState & NAT_E_NOPEER)
			{
				_AddLogLine(false, _T("Unconnected NatSock was deleted. server return E_NOPEER. %s."), UserHashToString(m_UserHash));
			}
			else
			{
				_AddLogLine(false, _T("Unconnected NatSock was deleted. time out. %s."), UserHashToString(m_UserHash));
			}
		}

		if(m_dwState & NAT_S_SYNC && time(NULL)-m_SendPingTime > PING_ATTEMPT_INTERVAL)
		{
			if(m_nPassivePing> PING_ATTEMPT_TIMES)
			{
				_AddLogLine(false, _T("Passive Unconnected NatSock was deleted. timeout. %s."), UserHashToString(m_UserHash));
				Failed();
			}
			else 
			{
				SendPingPacket();
			}
		}
	}
	catch(...)
	{
		//  the CAsyncSocketEx maybe is deleted
		Failed();
	}
}

int CTraverseBySourceExchange::SendConnectReq()
{
	if(m_dwState & NAT_E_TIMEOUT) return 1;

	m_SendReqTime = time(NULL);
	m_nSendReqCount++;
	m_dwNextSyncInterval = min(64, ExpoBackoff(SYNC_INIT_ATTEMPT_INTERVAL, m_nSendReqCount));

	CUpDownClient * pClient = theApp.clientlist->FindClientByUserHash(m_UserHash);

	if (pClient)
	{
		const CUpDownClient * pHighClient = pClient->GetSourceExchangeClient();

		
		//ASSERT(pHighClient); //COMMENTED by VC-fengwen on 2007/11/16 : 程序运行过程中帮自己打洞的HighId是有可能不在了的。已做了这方面的处理了。

		if (pHighClient == NULL)
		{
			return -1;
		}

		byte pack[1+1+16+16+4];
		pack[0]         = OP_EMULEPROT;
		pack[1]		    = OP_UDPSENATREQ;	
		memcpy(pack+2, m_UserHash, 16);
		memcpy(pack+18, thePrefs.GetUserHash(), 16);
		memcpy(pack+34, &m_dwConnAskNumber, 4);

		T_TRACE("\nSend UDP SourceExchange NAT Request, IP : %d PORT : %d!\n", pHighClient->GetIP(), pHighClient->GetUDPPort());

		return CNatSocket::SendPacket(pHighClient->GetIP(), htons(pHighClient->GetUDPPort()), pack, 1+1+16+16+4);
	}
	else
	{
		return -1;
	}
}

int CTraverseBySourceExchange::SendPingPacket()
{
	T_TRACE("\nSend Ping From Source Exchange, IP : %d Port : %d!\n", m_dwClientIp, ntohs(m_wClientPort));

	if(m_dwState & NAT_E_TIMEOUT) return 1;

	m_nPassivePing++;
	m_SendPingTime = time(NULL);

	_AddDebugLogLine(false, _T("send ping packet for %02X%02X%02X%02X. ConnAck=%08x\n"), m_UserHash[0],m_UserHash[1],m_UserHash[2],m_UserHash[3],
		m_dwConnAskNumber);

	if(m_dwClientIp && m_wClientPort)
	{
		uchar pack[20];
		GetMyUserHash(pack);
		memcpy(pack+16, &m_dwConnAskNumber, 4);
		return CNatSocket::SendPacket(m_dwClientIp, m_wClientPort, OP_NAT_PING, pack, 20);
	}

	return -1;
}

bool CTraverseBySourceExchange::Initialize()
{
	CUpDownClient * client= theApp.clientlist->FindClientByUserHash(m_UserHash);
	if(!client || !client->socket) return false;
	m_Sock = client->socket;

	return true;
}

bool CTraverseBySourceExchange::ProcessPacket(const uchar * data, int len, DWORD ip, WORD port)
{
	uint8 opcode=data[0];
	//UINT realsize=len-1;// VC-linhai[2007-08-06]:warning C4189: “realsize” : 局部变量已初始化但不引用
	const uchar * realdata=data+1;

	switch(opcode)
	{
	case OP_NAT_FAILED:
		assert(memcmp(realdata+1, m_UserHash, 16)==0);
		if(realdata[0]==1)
		{
			m_dwState |= NAT_E_NOPEER;
			//StopTraverse();
			return true;
		}
		break;
	case OP_NAT_SYNC2:
	case OP_NAT_SYNC:
		OnRecvSync(data, len, ip, port);
		return true;
	case OP_NAT_PING:
		OnRecvPing(data, len, ip, port);
		return true;
	}

	return false;
}

void CTraverseBySourceExchange::OnRecvSync(const uchar * data, int /*len*/, DWORD /*ip*/, WORD /*port*/)
{
	_AddDebugLogLine(false, _T("Receive NAT Sync Request From Source Exchange!\n"));

	//UINT realsize=len-1;// VC-linhai[2007-08-06]:warning C4189: “realsize” : 局部变量已初始化但不引用
	const uchar * realdata=data+1;

	DWORD cip = *(DWORD*)(realdata);
	WORD cport = *(WORD*)(realdata+4);

	if(cip==0 || cport==0)
	{
		return;
	}
	const uchar * id=realdata+6;

	DWORD ConnAck = 0;
	memcpy(&ConnAck, id+16, 4);

	_AddDebugLogLine(false, _T("recv sync, ConnAck=%08x\n"), ConnAck);
#ifdef _DEBUG
	in_addr addr;
	addr.s_addr = cip;
	_AddDebugLogLine(false, _T("peer addr of %02X%02X%02X%02X = %s:%d\n"), id[0], id[1], id[2],id[3],
		inet_ntoa(addr), ntohs(cport));
#endif
	uchar myid[16];
	GetMyUserHash(myid);
	if(memcmp(id, myid, 16)==0)
	{
		_AddLogLine(false, _T("ERROR: recv myself for traversal"));
		return;
	}

	CAsyncSocketEx * pASock=NULL;
	CUpDownClient * pClient= theApp.clientlist->FindClientByUserHash(id);
	if(pClient)
	{
		pASock = pClient->socket;

		if(! pASock)
		{
			CRuntimeClass * pClassSocket = RUNTIME_CLASS(CClientReqSocket);
			CClientReqSocket * socket = static_cast<CClientReqSocket*>(pClassSocket->CreateObject());
			socket->SetClient(pClient);
			if (!socket->Create())
			{
				socket->Safe_Delete();
				return;
			}

			pClient->socket = socket;
			pASock = socket;
		}
		ASSERT(pASock);
		if(! pASock) 
		{
			return;
		}
	}
	else
	{
		_AddDebugLogLine(false, _T("\n->%s: Accept a incoming sock for %02X%02X%02X%02X\n"), __FUNCTION__,
			id[0],id[1],id[2],id[3]);

		pASock = theApp.natthread->GetTempASock(id);
	}

	m_dwClientIp = cip;
	m_wClientPort = cport;

	m_dwState |=NAT_S_SYNC;
	SendPingPacket();
}

void CTraverseBySourceExchange::OnRecvPing(const uchar * data, int /*len*/, DWORD ip, WORD port)
{
	if( NULL==theApp.natthread )
		return;

	_AddDebugLogLine(false, _T("\nReceive Ping From Source Exchange!\n"));

	// For the strict design Process
	if (!(m_dwState & NAT_S_SYNC))
	{
		_AddDebugLogLine(false, _T("\nReceive Ping before Sync!\n"));
		return;
	}

	//UINT realsize=len-1;// VC-linhai[2007-08-06]:warning C4189: “realsize” : 局部变量已初始化但不引用
	const uchar * realdata=data+1;

	const uchar * hash=realdata;

	DWORD ConnAck=0;
	memcpy(&ConnAck, hash+16, 4);
	_AddDebugLogLine(false, _T("recv ping 3. %02X%02X%02X%02X, ConnAck=%d\n"), hash[0], hash[1], hash[2], hash[3],
		ConnAck);
	CAsyncSocketEx * pASock=NULL;

	if(ConnAck && !m_dwConnAskNumber)
		m_dwConnAskNumber = ConnAck;
	pASock = m_Sock;

	ASSERT(pASock);
	if(!pASock)
	{
		_AddDebugLogLine(false, _T("no AsyncsocketEx for unconnect sk\n"));
		Failed();
		return;
	}

	CNatSocket * nsock = theApp.natthread->FindNatSocket(hash);
	if(nsock)
	{
		Finish();
		return ;
	}

	nsock=new CNatSocket(pASock);
	nsock->m_dwConnAskNumber= m_dwConnAskNumber;
	sUserModeTCPConfig * tc=new sUserModeTCPConfig(ip, port);
	nsock->SetConfig(tc);

	nsock->m_TraversalType = CNatSocket::Traversal_byexchangesource;

	memcpy(nsock->GetUserHash(), hash, 16);

	theApp.natthread->AddNatSocket(pASock, nsock);
	theApp.natthread->RemoveUnconnSocket(hash);	//ADDED by VC-fengwen on 2007/10/15 : sock连通后，在unconnectsocket里要清除它。

	_AddLogLine(false, _T("NAT traversal connected. %s."), UserHashToString(hash));

	theApp.natthread->RemoveTempASock(hash);

	//pASock->TriggerEvent(FD_CONNECT);
	//pASock->TriggerEvent(FD_WRITE);
	CClientReqSocket * pClientSock = DYNAMIC_DOWNCAST(CClientReqSocket, pASock);
	if(pClientSock && pClientSock->client)
	{
		pClientSock->client->SetIP(ip);
		pClientSock->client->ResetIP2Country();
	}

	Finish();
}


