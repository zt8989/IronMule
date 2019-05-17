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
#pragma once
#include "UploadBandwidthThrottler.h" // ZZ:UploadBandWithThrottler (UDP)
#include "EncryptedDatagramSocket.h"
#include "./Neo/NeoConfig.h"
#include "./Neo/Address.h"
#include <map>

class Packet;

#pragma pack(1)
struct UDPPack
{
	Packet* packet;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	CAddress IP;
#else // NEO: IP6 END
	uint32	dwIP;
#endif
	uint16	nPort;
	uint32	dwTime;
	bool	bEncrypt;
	bool	bKad;
	uint32  nReceiverVerifyKey;
	uchar	pachTargetClientHashORKadID[16];
	//uint16 nPriority; We could add a priority system here to force some packets.
};
#pragma pack()

class CClientUDPSocket : public CAsyncSocket, public CEncryptedDatagramSocket, public ThrottledControlSocket // ZZ:UploadBandWithThrottler (UDP)
{
public:
	CClientUDPSocket();
	virtual ~CClientUDPSocket();

#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	void	SetConnectionEncryption(const CAddress& IP, uint16 nPort, bool bEncrypt, const uchar* pTargetClientHash = NULL);
	byte*	GetHashForEncryption(const CAddress& IP, uint16 nPort);
	bool	IsObfusicating(const CAddress& IP, uint16 nPort)	{return GetHashForEncryption(IP, nPort) != NULL;}
#else // NEO: IP6 END
	void	SetConnectionEncryption(uint32 dwIP, uint16 nPort, bool bEncrypt, const uchar* pTargetClientHash = NULL);
	byte*	GetHashForEncryption(uint32 dwIP, uint16 nPort);
	bool	IsObfusicating(uint32 dwIP, uint16 nPort)	{return GetHashForEncryption(dwIP, nPort) != NULL;}
#endif
	void	SendUtpPacket(const byte *data, size_t len, const struct sockaddr *to, socklen_t tolen);
#endif // NEO: NAT END

	bool	Create();
	bool	Rebind();
	uint16	GetConnectedPort()			{ return m_port; }
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	bool	SendPacket(Packet* packet, const CAddress& IP, uint16 nPort, bool bEncrypt, const uchar* pachTargetClientHashORKadID, bool bKad, uint32 nReceiverVerifyKey);
#else // NEO: IP6 END
	bool	SendPacket(Packet* packet, uint32 dwIP, uint16 nPort, bool bEncrypt, const uchar* pachTargetClientHashORKadID, bool bKad, uint32 nReceiverVerifyKey);
#endif
    SocketSentBytes  SendControlData(uint32 maxNumberOfBytesToSend, uint32 minFragSize); // ZZ:UploadBandWithThrottler (UDP)

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	bool	ProcessPacket(const BYTE* packet, UINT size, uint8 opcode, const CAddress& IP, uint16 port);
#else // NEO: IP6 END
	bool	ProcessPacket(const BYTE* packet, UINT size, uint8 opcode, uint32 ip, uint16 port);
#endif

protected:
	virtual void	OnSend(int nErrorCode);	
	virtual void	OnReceive(int nErrorCode);

private:
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	int		SendTo(char* lpBuf,int nBufLen,CAddress IP, uint16 nPort);
#else // NEO: IP6 END
	int		SendTo(char* lpBuf,int nBufLen,uint32 dwIP, uint16 nPort);
#endif
    bool	IsBusy() const { return m_bWouldBlock; }
	bool	m_bWouldBlock;
	uint16	m_port;

	CTypedPtrList<CPtrList, UDPPack*> controlpacket_queue;

    CCriticalSection sendLocker; // ZZ:UploadBandWithThrottler (UDP)

#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]
	struct SIpPort
	{
		uint16 nPort;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
		CAddress IP;
		bool operator< (const SIpPort &Other) const {
			if(IP.Type() != Other.IP.Type())
				return IP.Type() < Other.IP.Type();
			if(IP.Type() == CAddress::IPv6)
			{
				if(int cmp = memcmp(IP.Data(), Other.IP.Data(), 16))
					return cmp < 0;
			}
			else if(IP.Type() == CAddress::IPv4)
			{
				uint32 r = IP.ToIPv4();
				uint32 l = Other.IP.ToIPv4();
				if(r != l)
					return r < l;
			}
			else{
				ASSERT(0);
				return false;
			}
			return nPort < Other.nPort;
		}
#else // NEO: IP6 END
		uint32 dwIP;
		bool operator< (const SIpPort &Other) const {
			if(dwIP == Other.dwIP)
				return nPort < Other.nPort;
			return dwIP < Other.dwIP;
		}
#endif
	};

	struct SHash
	{
		byte	UserHash[16];
		uint32	LastUsed;
	};

	std::map<SIpPort, SHash>		m_HashMap;
#endif // NEO: NAT END
};
