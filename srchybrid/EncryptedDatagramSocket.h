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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#pragma once

#include "./Neo/NeoConfig.h"
#include "./Neo/Address.h"

class CEncryptedDatagramSocket
{
public:
	CEncryptedDatagramSocket();
	virtual ~CEncryptedDatagramSocket();

protected:
//#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]
//#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
//	int DecryptReceivedClient(BYTE* pbyBufIn, int nBufLen, BYTE** ppbyBufOut, const CAddress& IP, uint16 nPort, uint32* nReceiverVerifyKey, uint32* nSenderVerifyKey, bool* bEncrypted) const;
//#else // NEO: IP6 END
//	int DecryptReceivedClient(BYTE* pbyBufIn, int nBufLen, BYTE** ppbyBufOut, uint32 dwIP, uint16 nPort, uint32* nReceiverVerifyKey, uint32* nSenderVerifyKey, bool* bEncrypted) const;
//#endif
//#else // NEO: NAT END
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	int DecryptReceivedClient(BYTE* pbyBufIn, int nBufLen, BYTE** ppbyBufOut, const CAddress& IP, uint32* nReceiverVerifyKey, uint32* nSenderVerifyKey) const;
#else // NEO: IP6 END
	int DecryptReceivedClient(BYTE* pbyBufIn, int nBufLen, BYTE** ppbyBufOut, uint32 dwIP, uint32* nReceiverVerifyKey, uint32* nSenderVerifyKey) const;
#endif
//#endif
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	int EncryptSendClient(uchar** ppbyBuf, int nBufLen, const uchar* pachClientHashOrKadID, bool bKad, uint32 nReceiverVerifyKey, uint32 nSenderVerifyKey, bool bIPv6) const;
#else // NEO: IP6 END
	int EncryptSendClient(uchar** ppbyBuf, int nBufLen, const uchar* pachClientHashOrKadID, bool bKad, uint32 nReceiverVerifyKey, uint32 nSenderVerifyKey) const;
#endif
	
	int DecryptReceivedServer(BYTE* pbyBufIn, int nBufLen, BYTE** ppbyBufOut, uint32 dwBaseKey, uint32 dbgIP) const;
	int EncryptSendServer(uchar** ppbyBuf, int nBufLen, uint32 dwBaseKey) const;

};