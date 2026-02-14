/*
 * $Id: TraverseBySvr.cpp 11398 2009-03-17 11:00:27Z huby $
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
#include "stdafx.h"
#include "TraverseBySvr.h"

#include "../emule.h"
#include "NatThread.h"
#include "NatSocket.h"
#include "ClientList.h"
#include "updownclient.h"
#include "ListenSocket.h"
#include "ServerConnect.h"
#include "otherfunctions.h"
#include <cassert>

#ifdef _DEBUG_NAT
	extern void T_TRACE(char* fmt, ...);
#else
	#define T_TRACE
#endif

CTraverseBySvr::CTraverseBySvr(const uchar * uh, CTraverseStrategy * pNext)  : CTraverseStrategy(uh, pNext)
{
	m_dwTraverseIp = 0;
	m_wTraversePort = 0;

	m_Sock = NULL;

	m_SendPingTime = m_SendReqTime = m_SendConnAckTime = 0;
	m_nSendReqCount = 0;
	m_nSendPingCount = 0;
	m_nPassivePing = 0;

	m_bAcceptor = false;
	m_dwClientIp = 0;
	m_wClientPort = 0;

	m_dwState = 0;
	m_nSendConnAck = 0;
	m_dwConnAskNumber = GetTickCount();

	m_dwNextSyncInterval = SYNC_INIT_ATTEMPT_INTERVAL;
}

void CTraverseBySvr::StopTraverse()
{
	CTraverseStrategy * strategy=GetNextStrategy();
	SetNextStrategy(NULL);
	delete strategy;
}

void CTraverseBySvr::SendPacket()
{
	m_bFailed = m_dwState & NAT_E_NOPEER;

	try
	{
		//VC-fengwen on 2007/12/28 <begin> : 如果未连上服务器则直接fail
		if (theApp.natthread && !theApp.natthread->IsServerRegistered())
		{
			Failed();
			return;
		}
		//VC-fengwen on 2007/12/28 <end> : 如果未连上服务器则直接fail

		if(m_dwState & NAT_S_WAKEUP)
		{
			if(time(NULL)-m_SendPingTime >4)
			{
				if(m_nPassivePing> 15)
				{
					//  maybe try to next strategy
					//_AddLogLine(false, _T("Passive Unconnected NatSock was deleted. timeout. %s."), UserHashToString(m_UserHash));
					Failed();
				}
				else SendPingPacket();
			}
			return;
		}

		//VC-fengwen on 2007/12/28 <begin> : 修改sync的重试时间策略，防止对服务器的瞬时冲击。
		if (!m_bFailed )
		{
			if (m_dwState & NAT_S_SYNC) // 如果已经连上服务器但还没连上peer，则隔一段时间向服务器发一次sync以让服务器再作一次操作，以则增加成功机率。
			{
				if (m_nPassivePing > 0 && m_nPassivePing < PING_ATTEMPT_TIMES && time(NULL) - m_SendPingTime > PING_ATTEMPT_INTERVAL * 3)
				{
					SendConnectReq();
				}
			}
			else // 如果未连上服务器，则重试时间按指数退避。
			{
				if (time(NULL) - m_SendReqTime > m_dwNextSyncInterval)
				{
					if (m_nSendReqCount >= SYNC_ATTEMPT_TIMES)
					{
						m_dwState |= NAT_E_TIMEOUT;
						Failed();
					}
					else
					{
						if(m_nSendReqCount==0)
							_AddLogLine(false, _T("Begin to connect %s by Nat-traverse server."), UserHashToString(m_UserHash));
						SendConnectReq();
					}
				}
			}
		}
		//VC-fengwen on 2007/12/28 <end> : 修改sync的重试时间策略，防止对服务器的瞬时冲击。

		if(m_bFailed)
		{
			//if(m_Sock)// && pClientSock->client)
			//{
				//m_Sock->m_bUseNat = false;
			//}

			if(m_dwState & NAT_E_NOPEER)
			{
				//  maybe try to next strategy
				//_AddLogLine(false, _T("Unconnected NatSock was deleted. server return E_NOPEER. %s."), UserHashToString(m_UserHash));
			}
			else
			{
				//  maybe try to next strategy
				//_AddLogLine(false, _T("Unconnected NatSock was deleted. time out. %s."), UserHashToString(m_UserHash));
			}
		}

		if(m_dwState & NAT_S_SYNC && time(NULL)-m_SendPingTime > PING_ATTEMPT_INTERVAL)
		{
			if(m_nPassivePing > PING_ATTEMPT_TIMES)
			{
				//  maybe try to next strategy
				//_AddLogLine(false, _T("Passive Unconnected NatSock was deleted. timeout. %s."), UserHashToString(m_UserHash));
				Failed();
			}
			else SendPingPacket();
		}
	}
	catch(...)
	{
		AddDebugLogLine(false, _T("Exception: %s\n"), __FUNCTION__);
		//  the CAsyncSocketEx maybe is deleted
		Failed();
	}
}

int CTraverseBySvr::SendConnectReq()
{
	if(m_dwState & NAT_E_TIMEOUT) return 1;

	m_SendReqTime = time(NULL);
	m_nSendReqCount++;
	m_dwNextSyncInterval = min(64, ExpoBackoff(SYNC_INIT_ATTEMPT_INTERVAL, m_nSendReqCount));

	uchar pack[16*2+4];
	GetMyUserHash((uchar*)pack);
	memcpy(pack+16, &m_dwConnAskNumber, 4);
	memcpy(pack+20, m_UserHash, 16);

	AddDebugLogLine(false, _T("[NAT-SYNC] send OP_NAT_SYNC2 ask=%08x target=%s via %s:%u"),
		m_dwConnAskNumber, UserHashToString(m_UserHash), ipstr(m_dwTraverseIp), ntohs(m_wTraversePort));

	return CNatSocket::SendPacket(m_dwTraverseIp, m_wTraversePort, OP_NAT_SYNC2, pack, 16*2+4);
}

int CTraverseBySvr::SendPingPacket()
{
	if(m_dwState & NAT_E_TIMEOUT) return 1;

	m_nPassivePing++;
	m_SendPingTime = time(NULL);

/*	T_TRACE("send ping packet for %02X%02X%02X%02X. ConnAck=%08x\n", m_UserHash[0],m_UserHash[1],m_UserHash[2],m_UserHash[3],
		m_dwConnAskNumber);*/

	if(m_dwClientIp && m_wClientPort)
	{
		uchar pack[20];
		GetMyUserHash(pack);
		memcpy(pack+16, &m_dwConnAskNumber, 4);
		return CNatSocket::SendPacket(m_dwClientIp, m_wClientPort, OP_NAT_PING, pack, 20);
	}

	return -1;
}

bool CTraverseBySvr::Initialize()
{
	if( NULL==theApp.natthread )
		return false;

	theApp.natthread->GetTraversalSvr(m_dwTraverseIp, m_wTraversePort);
	if(!m_dwTraverseIp || !m_wTraversePort) return false;

	CUpDownClient * client= theApp.clientlist->FindClientByUserHash(m_UserHash);
	if(!client || !client->socket) return false;
	m_Sock = client->socket;

	CNatSocket * nsock=theApp.natthread->WakeupNatSocketFromPool(m_UserHash);
	if(nsock)
	{
		nsock->m_dwConnAskNumber = m_dwConnAskNumber;

		m_dwState = NAT_S_WAKEUP;
		m_dwClientIp = nsock->GetTargetIP();
		m_wClientPort = nsock->GetTargetPort();
	}
	return true;
}

bool CTraverseBySvr::ProcessPacket(const uchar * data, int len, DWORD ip, WORD port)
{
	if(NULL==m_Sock)
		return false;

	CClientReqSocket * pClientSock = DYNAMIC_DOWNCAST(CClientReqSocket, m_Sock);

	if( pClientSock && pClientSock->IsDeleteThis())
		return false;

	uint8 opcode=data[0];
	//UINT realsize=len-1;
	const uchar * realdata=data+1;

	switch(opcode)
	{
	case OP_NAT_FAILED:
		assert(memcmp(realdata+1, m_UserHash, 16)==0);
		if(realdata[0]==1)
		{
			m_dwState |= NAT_E_NOPEER;
#ifdef _DEBUG_NAT
			AddDebugLogLine(false, _T("*** Server tell no Registered Peer about %s\n"), UserHashToString(m_UserHash));
#endif
			Failed();
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

void CTraverseBySvr::OnRecvSync(const uchar * data, int /*len*/, DWORD /*ip*/, WORD /*port*/)
{
	//UINT realsize=len-1;
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
	AddDebugLogLine(false, _T("[NAT-SYNC] recv OP_NAT_SYNC/2 peer=%s:%u ask=%08x user=%s"),
		ipstr(cip), ntohs(cport), ConnAck, UserHashToString(id));

	T_TRACE("recv sync, ConnAck=%08x\n", ConnAck);
#ifdef _DEBUG
	in_addr addr;
	addr.s_addr = cip;
	T_TRACE("peer addr of %02X%02X%02X%02X = %s:%d\n", id[0], id[1], id[2],id[3],
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
		if(! pASock) return;
	}
	else
	{
		T_TRACE("\n->%s: Accept a incoming sock for %02X%02X%02X%02X\n", __FUNCTION__,
			id[0],id[1],id[2],id[3]);

		if( theApp.natthread )
			pASock = theApp.natthread->GetTempASock(id);
	}

	m_dwClientIp = cip;
	m_wClientPort = cport;

	m_dwState |=NAT_S_SYNC;
	SendPingPacket();
}

void CTraverseBySvr::OnRecvPing(const uchar * data, int /*len*/, DWORD ip, WORD port)
{
	//UINT realsize=len-1;
	const uchar * realdata=data+1;

	const uchar * hash=realdata;

	DWORD ConnAck=0;
	memcpy(&ConnAck, hash+16, 4);
	T_TRACE("recv ping 4. %02X%02X%02X%02X, ConnAck=%d\n", hash[0], hash[1], hash[2], hash[3],
		ConnAck);
	CAsyncSocketEx * pASock=NULL;

	if(ConnAck && ConnAck!=m_dwConnAskNumber)
		m_dwConnAskNumber = ConnAck;
	pASock = m_Sock;

	ASSERT(pASock);
	if(!pASock)
	{
		T_TRACE("no AsyncsocketEx for unconnect sk\n");
		Failed();
		return;
	}

	CNatSocket * nsock = NULL;
	
	if( theApp.natthread )
	{
		theApp.natthread->FindNatSocket(hash);

		if(nsock)
		{
			if( nsock->GetParent()!=pASock )
			{
				theApp.natthread->ResetNatSocket(nsock->GetParent(), pASock);
			}
			//pASock->TriggerEvent(FD_CONNECT);
			//pASock->TriggerEvent(FD_WRITE);
			Finish();
			return ;
		}
	}	

	nsock=new CNatSocket(pASock);
	nsock->m_dwConnAskNumber= m_dwConnAskNumber;
	sUserModeTCPConfig * tc=new sUserModeTCPConfig(ip, port);
	nsock->SetConfig(tc);

	nsock->m_TraversalType = CNatSocket::Traversal_bysvr;
//	nsock->m_bTraverseBySvr= true;
//	m_dwTraverseBySvr++;

	memcpy(nsock->GetUserHash(), hash, 16);

	if( theApp.natthread )
	{
		theApp.natthread->AddNatSocket(pASock, nsock);
		theApp.natthread->RemoveUnconnSocket(hash);	//ADDED by VC-fengwen on 2007/10/15 : sock连通后，在unconnectsocket里要清除它。

		_AddLogLine(false, _T("NAT traversal connected. %s."), UserHashToString(hash));

		theApp.natthread->RemoveTempASock(hash);
	}

	//pASock->TriggerEvent(FD_CONNECT);
	//pASock->TriggerEvent(FD_WRITE);
	CClientReqSocket * pClientSock = DYNAMIC_DOWNCAST(CClientReqSocket, pASock);
	if(pClientSock && pClientSock->client)
	{
		pClientSock->client->SetIP(ip);
		pClientSock->client->ResetIP2Country();
	}
	T_TRACE("*********** notify connect sock=%08x, client=%08x\n", pASock, pClientSock->client);
	Finish();
}



