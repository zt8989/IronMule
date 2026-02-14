/*
 * $Id: SourceExchangeNAT.h 4483 2008-01-02 09:19:06Z soarchin $
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

class CClientReqSocket;
class CUpDownClient;

// VC-SearchDream[2007-04-18]: For SourceExchange NAT Begin
enum EUDPState
{
	UDP_DISCONNECT = 0,
	UDP_CONNECTED  = 1
};
// VC-SearchDream[2007-04-18]: For SourceExchange NAT End

class CSourceExchangeNAT
{
public:

	CSourceExchangeNAT();
	virtual ~CSourceExchangeNAT();

	static void CheckUDPTunnel(CUpDownClient * pClient);

	static bool ProcessUDPPacket(const BYTE* packet, UINT size, uint8 opcode, uint32 ip, uint16 port);
	static bool ProcessTCPPacket(const BYTE* packet, uint32 size, UINT opcode, UINT uRawSize, CClientReqSocket * socket);

protected:

	static void CheckConnection(CUpDownClient * pClient);
	static void CheckForTimeOut(CUpDownClient * pClient);

	static bool SendUDPPacket(DWORD ip, WORD port, const uchar * data, int len, CUpDownClient * pClient);
};
