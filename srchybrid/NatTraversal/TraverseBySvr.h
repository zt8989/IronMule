/*
 * $Id: TraverseBySvr.h 4789 2008-02-14 08:59:23Z fengwen $
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
#pragma once
#include "TraverseStrategy.h"
#include "ClientList.h"
#include "updownclient.h"
#include "ListenSocket.h"
#include "ServerConnect.h"

class CTraverseBySvr : public CTraverseStrategy
{
public:
	CTraverseBySvr(const uchar * uh, CTraverseStrategy * pNext);

	virtual bool Initialize();
	virtual void SendPacket();
	virtual bool ProcessPacket(const uchar * data, int len, DWORD ip, WORD port);
private:
	void StopTraverse();
	int SendConnectReq();
	int SendPingPacket();
	void OnRecvSync(const uchar * data, int len, DWORD ip, WORD port);
	void OnRecvPing(const uchar * data, int len, DWORD ip, WORD port);

	DWORD m_dwTraverseIp;
	WORD m_wTraversePort;

	int			m_nSendReqCount ,m_nSendPingCount , m_nSendConnAck;
	int			m_nPassivePing;
	DWORD		m_SendReqTime, m_SendPingTime, m_SendConnAckTime;
	DWORD		m_dwClientIp;
	WORD		m_wClientPort;
	CAsyncSocketEx * m_Sock;

	bool		m_bAcceptor;
	bool		m_bByBuddy;
	bool		m_bPunchCompletedLogged;
	DWORD		m_dwState;
	DWORD		m_dwConnAskNumber;

	
	enum {SYNC_INIT_ATTEMPT_INTERVAL = 2, SYNC_ATTEMPT_TIMES = 8, PING_ATTEMPT_TIMES = 15, PING_ATTEMPT_INTERVAL = 4};
	DWORD	m_dwNextSyncInterval;	//VC-fengwen on 2007/12/27 : 通过服务器打洞的重试时间使用指数退避。
};
