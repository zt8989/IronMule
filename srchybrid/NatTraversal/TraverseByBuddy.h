/*
 * $Id: TraverseByBuddy.h 4483 2008-01-02 09:19:06Z soarchin $
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

class CTraverseByBuddy : public CTraverseStrategy
{
public:
	CTraverseByBuddy(const uchar * uh, CTraverseStrategy * pNext);

	virtual bool Initialize();
	virtual void SendPacket();
	virtual bool ProcessPacket(const uchar * data, int len, DWORD ip, WORD port);
private:
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
	DWORD		m_dwState;
	DWORD		m_dwConnAskNumber;
};
