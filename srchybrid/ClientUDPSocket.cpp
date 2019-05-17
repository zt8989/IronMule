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
#include "emule.h"
#include "ClientUDPSocket.h"
#include "Packets.h"
#include "DownloadQueue.h"
#include "Statistics.h"
#include "PartFile.h"
#include "SharedFileList.h"
#include "UploadQueue.h"
#include "UpDownClient.h"
#include "Preferences.h"
#include "OtherFunctions.h"
#include "SafeFile.h"
#include "ClientList.h"
#include "Listensocket.h"
#include <zlib/zlib.h>
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/UDPFirewallTester.h"
#include "kademlia/net/KademliaUDPListener.h"
#include "kademlia/io/IOException.h"
#include "IPFilter.h"
#include "Log.h"
#include "EncryptedDatagramSocket.h"
#include "./kademlia/kademlia/prefs.h"
#include "./kademlia/utils/KadUDPKey.h"
#include "./Neo/UtpSocket.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


// CClientUDPSocket

CClientUDPSocket::CClientUDPSocket()
{
	m_bWouldBlock = false;
	m_port=0;
}

CClientUDPSocket::~CClientUDPSocket()
{
    theApp.uploadBandwidthThrottler->RemoveFromAllQueues(this); // ZZ:UploadBandWithThrottler (UDP)

    POSITION pos = controlpacket_queue.GetHeadPosition();
	while (pos){
		UDPPack* p = controlpacket_queue.GetNext(pos);
		delete p->packet;
		delete p;
	}
}

#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
void CClientUDPSocket::SetConnectionEncryption(const CAddress& IP, uint16 nPort, bool bEncrypt, const uchar* pTargetClientHash){
	SIpPort IpPort = {nPort, IP};
#else // NEO: IP6 END
void CClientUDPSocket::SetConnectionEncryption(uint32 dwIP, uint16 nPort, bool bEncrypt, const uchar* pTargetClientHash){
	SIpPort IpPort = {nPort, dwIP};
#endif
	std::map<SIpPort, SHash>::iterator I = m_HashMap.find(IpPort);
	if(bEncrypt)
	{
		if(I == m_HashMap.end())
		{
			SHash Hash;
			if(pTargetClientHash)
				md4cpy(Hash.UserHash, pTargetClientHash);
			else
				md4clr(Hash.UserHash);
			I = m_HashMap.insert(std::map<SIpPort, SHash>::value_type(IpPort, Hash)).first;
		}
		I->second.LastUsed = ::GetTickCount();
	}
	else if(I != m_HashMap.end())
		m_HashMap.erase(I);
}

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
byte* CClientUDPSocket::GetHashForEncryption(const CAddress& IP, uint16 nPort){
	SIpPort IpPort = {nPort, IP};
#else // NEO: IP6 END
byte* CClientUDPSocket::GetHashForEncryption(uint32 dwIP, uint16 nPort){
	SIpPort IpPort = {nPort, dwIP};
#endif
	std::map<SIpPort, SHash>::iterator I = m_HashMap.find(IpPort);
	if(I == m_HashMap.end())
		return NULL;
	I->second.LastUsed = ::GetTickCount();
	// Note: if we dont know how to encrypt but have got a incomming encrypted packet, 
	//	we use our own hash to encrpt as we expect the remote side to know it and try it.
//	if(isnulmd4(I->second.UserHash))
//		md4cpy(Hash.UserHash, thePrefs.GetUserHash());
	return I->second.UserHash;
}

union UUtpHdr
{
	uint32 Bits;
	struct SUtpHdr
	{
		uint32
		ver:	4,
		type:	4,
		ext:	8,
		connid:	16;
	} Fields;
};

void CClientUDPSocket::SendUtpPacket(const byte *data, size_t len, const struct sockaddr *to, socklen_t tolen)
{
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	CAddress IP;
	uint16 nPort;
	IP.FromSA(to, tolen, &nPort);
	byte* pTargetClientHash = GetHashForEncryption(IP, nPort);
#else // NEO: IP6 END
	byte* pTargetClientHash = GetHashForEncryption(((SOCKADDR_IN*)to)->sin_addr.S_un.S_addr, ntohs(((SOCKADDR_IN*)to)->sin_port));
#endif

	ASSERT(len >= 4);

	UUtpHdr UtpHdr;
	UtpHdr.Bits = *((uint32*)data);
	if(pTargetClientHash && UtpHdr.Fields.type == 4) // ST_SYN
	{
		CSafeMemFile data_out(128);
		data_out.WriteHash16(thePrefs.GetUserHash());
		Packet* packet = new Packet(&data_out, OP_UDPRESERVEDPROT2);
		packet->opcode = 0xFF; // Key Frame
		theStats.AddUpDataOverheadOther(packet->size);
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
		SendPacket(packet, IP, nPort, pTargetClientHash != NULL, pTargetClientHash, false, 0);
#else // NEO: IP6 END
		SendPacket(packet, ((SOCKADDR_IN*)to)->sin_addr.S_un.S_addr, ntohs(((SOCKADDR_IN*)to)->sin_port), pTargetClientHash != NULL, pTargetClientHash, false, 0);
#endif
	}

	Packet* frame = new Packet(OP_UDPRESERVEDPROT2);
	frame->opcode = 0x00; // UTP Frame
	frame->pBuffer = new char[len];
	memcpy(frame->pBuffer, data, len);
	frame->size = len;

	//theStats.AddUpDataOverheadOther(0); // its counted as TCP elseware

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	SendPacket(frame, IP, nPort, pTargetClientHash != NULL, pTargetClientHash, false, 0);
#else // NEO: IP6 END
	SendPacket(frame, ((SOCKADDR_IN*)to)->sin_addr.S_un.S_addr, ntohs(((SOCKADDR_IN*)to)->sin_port), pTargetClientHash != NULL, pTargetClientHash, false, 0);
#endif
}
#endif // NEO: NAT END

void CClientUDPSocket::OnReceive(int nErrorCode)
{
	if (nErrorCode)
	{
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket, error on receive event: %s"), GetErrorMessage(nErrorCode, 1));
	}

	BYTE buffer[5000];
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	SOCKADDR_IN6 sockAddr;
	int iSockAddrLen = sizeof sockAddr;
	int nRealLen = ReceiveFrom(buffer, sizeof buffer, (SOCKADDR*)&sockAddr, &iSockAddrLen);
	CAddress IP;
	uint16 nPort;
	IP.FromSA((SOCKADDR*)&sockAddr, iSockAddrLen, &nPort);
	IP.Convert(CAddress::IPv4); // check if its a maped IPv4 address

	// IPv6-TODO: Add IPv6 ban list
	if (IP.Type() == CAddress::IPv4 && (theApp.ipfilter->IsFiltered(_ntohl(IP.ToIPv4())) || theApp.clientlist->IsBannedClient(_ntohl(IP.ToIPv4()))))
		return;

#else // NEO: IP6 END
	SOCKADDR_IN sockAddr = {0};
	int iSockAddrLen = sizeof sockAddr;
	int nRealLen = ReceiveFrom(buffer, sizeof buffer, (SOCKADDR*)&sockAddr, &iSockAddrLen);

	if (!(theApp.ipfilter->IsFiltered(sockAddr.sin_addr.S_un.S_addr) || theApp.clientlist->IsBannedClient(sockAddr.sin_addr.S_un.S_addr)))
#endif
	{
		BYTE* pBuffer;
		uint32 nReceiverVerifyKey;
		uint32 nSenderVerifyKey;
//#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]
//		bool bEncrypted = false;
//#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
//		int nPacketLen = DecryptReceivedClient(buffer, nRealLen, &pBuffer, IP, &nReceiverVerifyKey, &nSenderVerifyKey, &bEncrypted);
//#else // NEO: IP6 END
//		int nPacketLen = DecryptReceivedClient(buffer, nRealLen, &pBuffer, sockAddr.sin_addr.S_un.S_addr, &nReceiverVerifyKey, &nSenderVerifyKey, &bEncrypted);
//#endif
//#else // NEO: NAT END
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
		int nPacketLen = DecryptReceivedClient(buffer, nRealLen, &pBuffer, IP, &nReceiverVerifyKey, &nSenderVerifyKey);
#else // NEO: IP6 END
		int nPacketLen = DecryptReceivedClient(buffer, nRealLen, &pBuffer, sockAddr.sin_addr.S_un.S_addr, &nReceiverVerifyKey, &nSenderVerifyKey);
#endif
//#endif
		if (nPacketLen >= 1)
		{
			CString strError;
			try
			{
				switch (pBuffer[0])
				{
					case OP_EMULEPROT:
					{
						if (nPacketLen >= 2)
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
							ProcessPacket(pBuffer+2, nPacketLen-2, pBuffer[1], IP, nPort);
#else // NEO: IP6 END
							ProcessPacket(pBuffer+2, nPacketLen-2, pBuffer[1], sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port));
#endif
						else
							throw CString(_T("eMule packet too short"));
						break;
					}
					case OP_KADEMLIAPACKEDPROT:
					{
						theStats.AddDownDataOverheadKad(nPacketLen);
						if (nPacketLen >= 2)
						{
							uint32 nNewSize = nPacketLen*10+300;
							BYTE* unpack = NULL;
							uLongf unpackedsize = 0;
							int iZLibResult = 0;
							do {
								delete[] unpack;
								unpack = new BYTE[nNewSize];
								unpackedsize = nNewSize-2;
								iZLibResult = uncompress(unpack+2, &unpackedsize, pBuffer+2, nPacketLen-2);
								nNewSize *= 2; // size for the next try if needed
							} while (iZLibResult == Z_BUF_ERROR && nNewSize < 250000);

							if (iZLibResult == Z_OK)
							{
								unpack[0] = OP_KADEMLIAHEADER;
								unpack[1] = pBuffer[1];
								try
								{
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
									Kademlia::CKademlia::ProcessPacket(unpack, unpackedsize+2, IP.ToIPv4(), nPort
										, (Kademlia::CPrefs::GetUDPVerifyKey(_ntohl(IP.ToIPv4())) == nReceiverVerifyKey)
										, Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP(false)) );
#else // NEO: IP6 END
									Kademlia::CKademlia::ProcessPacket(unpack, unpackedsize+2, ntohl(sockAddr.sin_addr.S_un.S_addr), ntohs(sockAddr.sin_port)
										, (Kademlia::CPrefs::GetUDPVerifyKey(sockAddr.sin_addr.S_un.S_addr) == nReceiverVerifyKey)
										, Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP(false)) );
#endif
								}
								catch(...)
								{
									delete[] unpack;
									throw;
								}
							}
							else
							{
								delete[] unpack;
								CString strError;
								strError.Format(_T("Failed to uncompress Kad packet: zip error: %d (%hs)"), iZLibResult, zError(iZLibResult));
								throw strError;
							}
							delete[] unpack;
						}
						else
							throw CString(_T("Kad packet (compressed) too short"));
						break;
					}
					case OP_KADEMLIAHEADER:
					{
						theStats.AddDownDataOverheadKad(nPacketLen);
						//zz_fly :: Anti-Leecher
						//note: Clients sending a KAD tag from 0.49a+ but pretending to be 0.48a
						byte byOpcode = pBuffer[1];
						if(byOpcode == KADEMLIA_FIREWALLED2_REQ)
						{
							CUpDownClient* client = theApp.clientlist->FindClientByIP(IP);
							if(client != NULL && client->GetClientSoft() == SO_EMULE && client->GetVersion() != 0 && client->GetVersion() < MAKE_CLIENT_VERSION(0, 49, 0))
							{
								client->BanLeecher(_T("Detected Vagaa"),5); //Bad Leecher, Hard Ban
								break;
							}
						}
						//zz_fly :: Anti-Leecher end
						if (nPacketLen >= 2)
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
							Kademlia::CKademlia::ProcessPacket(pBuffer, nPacketLen, IP.ToIPv4(), nPort
							, (Kademlia::CPrefs::GetUDPVerifyKey(_ntohl(IP.ToIPv4())) == nReceiverVerifyKey)
							, Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP(false)) );
#else // NEO: IP6 END
							Kademlia::CKademlia::ProcessPacket(pBuffer, nPacketLen, ntohl(sockAddr.sin_addr.S_un.S_addr), ntohs(sockAddr.sin_port)
							, (Kademlia::CPrefs::GetUDPVerifyKey(_ntohl(IP.ToIPv4())) == nReceiverVerifyKey)
							, Kademlia::CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP(false)) );
#endif
						else
							throw CString(_T("Kad packet too short"));
						break;
					}
#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]
					case OP_UDPRESERVEDPROT2:
					{
						// Note: here we dont have opcodes, just [uint8 - Prot][n bytes - data]
						if (nPacketLen >= 2)
						{
//#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
							//if(bEncrypted && !IsObfusicating(IP, nPort))
							//	SetConnectionEncryption(IP, nPort, true);
//#else // NEO: IP6 END
							//if(bEncrypted && !IsObfusicating(sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port)))
							//	SetConnectionEncryption(sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port), true);
//#endif
							if(pBuffer[1] == 0x00) // UTP Frame
							{
								//theStats.AddUpDataOverheadOther(0); // its counted as TCP elseware
								CUtpSocket::ProcessUtpPacket(pBuffer+2, nPacketLen-2, (struct sockaddr*)&sockAddr, iSockAddrLen);
							}
							else if(pBuffer[1] == 0xFF) // Key Frame
							{
								int size = nPacketLen-2;
								const BYTE* packet = pBuffer+2;
								if(size < + 16)
									throw CString(_T("Key packet too short"));

								theStats.AddUpDataOverheadOther(size);
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
								SetConnectionEncryption(IP, nPort, packet);
#else // NEO: IP6 END
								SetConnectionEncryption(sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port), packet);
#endif
							}
						}
						else
							throw CString(_T("Utp packet too short"));
						break;
					}
#endif // NEO: NAT END
					default:
					{
						CString strError;
						strError.Format(_T("Unknown protocol 0x%02x"), pBuffer[0]);
						throw strError;
					}
				}
			}
			catch(CFileException* error)
			{
				error->Delete();
				strError = _T("Invalid packet received");
			}
			catch(CMemoryException* error)
			{
				error->Delete();
				strError = _T("Memory exception");
			}
			catch(CString error)
			{
				strError = error;
			}
			catch(Kademlia::CIOException* error)
			{
				error->Delete();
				strError = _T("Invalid packet received");
			}
			catch(CException* error)
			{
				error->Delete();
				strError = _T("General packet error");
			}
	#ifndef _DEBUG
			catch(...)
			{
				strError = _T("Unknown exception");
				ASSERT(0);
			}
	#endif
			if (thePrefs.GetVerbose() && !strError.IsEmpty())
			{
				CString strClientInfo;
				CUpDownClient* client;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
				if (pBuffer[0] == OP_EMULEPROT)
					client = theApp.clientlist->FindClientByIP_UDP(IP, nPort);
				else
					client = theApp.clientlist->FindClientByIP_KadPort(IP, nPort);
				if (client)
					strClientInfo = client->DbgGetClientInfo();
				else
					strClientInfo.Format(_T("%s:%u"), IP.ToStringW().c_str(), nPort);
#else // NEO: IP6 END
				if (pBuffer[0] == OP_EMULEPROT)
					client = theApp.clientlist->FindClientByIP_UDP(sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port));
				else
					client = theApp.clientlist->FindClientByIP_KadPort(sockAddr.sin_addr.S_un.S_addr, ntohs(sockAddr.sin_port));
				if (client)
					strClientInfo = client->DbgGetClientInfo();
				else
					strClientInfo.Format(_T("%s:%u"), ipstr(sockAddr.sin_addr), ntohs(sockAddr.sin_port));
#endif

				DebugLogWarning(_T("Client UDP socket: prot=0x%02x  opcode=0x%02x  sizeaftercrypt=%u realsize=%u  %s: %s"), pBuffer[0], pBuffer[1], nPacketLen, nRealLen, strError, strClientInfo);
			}
		}
		else if (nPacketLen == SOCKET_ERROR)
		{
			DWORD dwError = WSAGetLastError();
			if (dwError == WSAECONNRESET)
			{
				// Depending on local and remote OS and depending on used local (remote?) router we may receive
				// WSAECONNRESET errors. According some KB articles, this is a special way of winsock to report 
				// that a sent UDP packet was not received by the remote host because it was not listening on 
				// the specified port -> no eMule running there.
				//
				// TODO: So, actually we should do something with this information and drop the related Kad node 
				// or eMule client...
				;
			}
			if (thePrefs.GetVerbose() && dwError != WSAECONNRESET)
			{
				CString strClientInfo;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
				if (iSockAddrLen > 0 && !IP.IsNull())
					strClientInfo.Format(_T(" from %s:%u"), IP.ToStringW().c_str(), nPort);
#else // NEO: IP6 END
				if (iSockAddrLen > 0 && sockAddr.sin_addr.S_un.S_addr != 0 && sockAddr.sin_addr.S_un.S_addr != INADDR_NONE)
					strClientInfo.Format(_T(" from %s:%u"), ipstr(sockAddr.sin_addr), ntohs(sockAddr.sin_port));
#endif
				DebugLogError(_T("Error: Client UDP socket, failed to receive data%s: %s"), strClientInfo, GetErrorMessage(dwError, 1));
			}
		}
	}
}

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
bool CClientUDPSocket::ProcessPacket(const BYTE* packet, UINT size, uint8 opcode, const CAddress& ip, uint16 port)
#else // NEO: IP6 END
bool CClientUDPSocket::ProcessPacket(const BYTE* packet, UINT size, uint8 opcode, uint32 ip, uint16 port)
#endif
{
	switch(opcode)
	{
		case OP_REASKCALLBACKUDP:
		{
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_ReaskCallbackUDP", NULL, NULL, ip);
			theStats.AddDownDataOverheadOther(size);
			CUpDownClient* buddy = theApp.clientlist->GetBuddy();
			if( buddy )
			{
				if( size < 17 || buddy->socket == NULL )
					break;
				if (!md4cmp(packet, buddy->GetBuddyID()))
				{
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
					byte head[4+16+2];
					int len = 6;
					if(ip.Type() == CAddress::IPv6)
					{
						len += 16;
						PokeUInt32(head, 0);
						memcpy(head+4, ip.Data(), 16);
						PokeUInt16(head+20, port);
					}
					else
					{
						PokeUInt32(head, _ntohl(ip.ToIPv4()));
						PokeUInt16(head+4, port);
					}

					Packet* response = new Packet(OP_EMULEPROT);
					response->opcode = OP_REASKCALLBACKTCP;
					response->pBuffer = new char[len + size-16];
					memcpy(response->pBuffer, head, len);
					memcpy(response->pBuffer + len, packet+16, size-16);
					response->size = len + size-16;
#else // NEO: IP6 END
					PokeUInt32(const_cast<BYTE*>(packet)+10, ip);
					PokeUInt16(const_cast<BYTE*>(packet)+14, port);
					Packet* response = new Packet(OP_EMULEPROT);
					response->opcode = OP_REASKCALLBACKTCP;
					response->pBuffer = new char[size];
					memcpy(response->pBuffer, packet+10, size-10);
					response->size = size-10;
#endif
					if (thePrefs.GetDebugClientTCPLevel() > 0)
						DebugSend("OP__ReaskCallbackTCP", buddy);
					theStats.AddUpDataOverheadFileRequest(response->size);
					buddy->SendPacket(response, true);
				}
			}
			break;
		}
#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]
		case OP_RENDEZVOUS:
		{
			CSafeMemFile data(packet, size);
			// Note: we dont get here form the socket directly but from our boddy, the IP and port argumetns are the one seen by the buddy
			uchar uchUserHash[16];
			data.ReadHash16(uchUserHash);
			uint8 byConnectOptions = data.ReadUInt8();

			CUpDownClient* callback;
			callback = theApp.clientlist->FindClientByIP_UDP(ip, port);
			if( callback == NULL )
			{
				callback = new CUpDownClient(NULL,0,ip,0,0);
				callback->SetKadPort(port);
				theApp.clientlist->AddClient(callback);
			}
			callback->SetConnectOptions(byConnectOptions, true, true);
			callback->SetNatTraversalSupport(true);
			callback->TryToConnect(true, false, NULL, true);
		}
		case OP_HOLEPUNCH:
			break;
#endif // NEO: NAT END
		case OP_REASKFILEPING:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CSafeMemFile data_in(packet, size);
			uchar reqfilehash[16];
			data_in.ReadHash16(reqfilehash);
			CKnownFile* reqfile = theApp.sharedfiles->GetFileByID(reqfilehash);
			
			bool bSenderMultipleIpUnknown = false;
			CUpDownClient* sender = theApp.uploadqueue->GetWaitingClientByIP_UDP(ip, port, true, &bSenderMultipleIpUnknown);
			if (!reqfile)
			{
				if (thePrefs.GetDebugClientUDPLevel() > 0) {
					DebugRecv("OP_ReaskFilePing", NULL, reqfilehash, ip);
					DebugSend("OP__FileNotFound", NULL);
				}

				Packet* response = new Packet(OP_FILENOTFOUND,0,OP_EMULEPROT);
				theStats.AddUpDataOverheadFileRequest(response->size);
				if (sender != NULL)
					SendPacket(response, ip, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
				else
					SendPacket(response, ip, port, false, NULL, false, 0);
				break;
			}
			if (sender)
			{
				if (thePrefs.GetDebugClientUDPLevel() > 0)
					DebugRecv("OP_ReaskFilePing", sender, reqfilehash);

				//Make sure we are still thinking about the same file
				if (md4cmp(reqfilehash, sender->GetUploadFileID()) == 0)
				{
					sender->AddAskedCount();
					sender->SetLastUpRequest();
					//I messed up when I first added extended info to UDP
					//I should have originally used the entire ProcessExtenedInfo the first time.
					//So now I am forced to check UDPVersion to see if we are sending all the extended info.
					//For now on, we should not have to change anything here if we change
					//anything to the extended info data as this will be taken care of in ProcessExtendedInfo()
					//Update extended info. 
					if (sender->GetUDPVersion() > 3)
					{
						sender->ProcessExtendedInfo(&data_in, reqfile);
					}
					//Update our complete source counts.
					else if (sender->GetUDPVersion() > 2)
					{
						uint16 nCompleteCountLast= sender->GetUpCompleteSourcesCount();
						uint16 nCompleteCountNew = data_in.ReadUInt16();
						sender->SetUpCompleteSourcesCount(nCompleteCountNew);
						if (nCompleteCountLast != nCompleteCountNew)
						{
							reqfile->UpdatePartsInfo();
						}
					}
					CSafeMemFile data_out(128);
					if(sender->GetUDPVersion() > 3)
					{
						if (reqfile->IsPartFile())
							((CPartFile*)reqfile)->WritePartStatus(&data_out);
						else
							data_out.WriteUInt16(0);
					}
					data_out.WriteUInt16((uint16)(theApp.uploadqueue->GetWaitingPosition(sender)));
					if (thePrefs.GetDebugClientUDPLevel() > 0)
						DebugSend("OP__ReaskAck", sender);
					Packet* response = new Packet(&data_out, OP_EMULEPROT);
					response->opcode = OP_REASKACK;
					theStats.AddUpDataOverheadFileRequest(response->size);
					SendPacket(response, ip, port, sender->ShouldReceiveCryptUDPPackets(), sender->GetUserHash(), false, 0);
				}
				else
				{
					DebugLogError(_T("Client UDP socket; ReaskFilePing; reqfile does not match"));
					TRACE(_T("reqfile:         %s\n"), DbgGetFileInfo(reqfile->GetFileHash()));
					TRACE(_T("sender->GetRequestFile(): %s\n"), sender->GetRequestFile() ? DbgGetFileInfo(sender->GetRequestFile()->GetFileHash()) : _T("(null)"));
				}
			}
			else
			{
				if (thePrefs.GetDebugClientUDPLevel() > 0)
					DebugRecv("OP_ReaskFilePing", NULL, reqfilehash, ip);
				// Don't answer him. We probably have him on our queue already, but can't locate him. Force him to establish a TCP connection
				if (!bSenderMultipleIpUnknown){
					if (((uint32)theApp.uploadqueue->GetWaitingUserCount() + 50) > thePrefs.GetQueueSize())
					{
						if (thePrefs.GetDebugClientUDPLevel() > 0)
							DebugSend("OP__QueueFull", NULL);
						Packet* response = new Packet(OP_QUEUEFULL,0,OP_EMULEPROT);
						theStats.AddUpDataOverheadFileRequest(response->size);
						SendPacket(response, ip, port, false, NULL, false, 0); // we cannot answer this one encrypted since we dont know this client
					}
				}
				else{
					DebugLogWarning(_T("UDP Packet received - multiple clients with the same IP but different UDP port found. Possible UDP Portmapping problem, enforcing TCP connection. IP: %s, Port: %u"), ipstr(ip), port); 
				}
			}
			break;
		}
		case OP_QUEUEFULL:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_QueueFull", sender, NULL, ip);
			if (sender && sender->UDPPacketPending()){
				sender->SetRemoteQueueFull(true);
				sender->UDPReaskACK(0);
			}
			else if (sender != NULL)
				DebugLogError(_T("Received UDP Packet (OP_QUEUEFULL) which was not requested (pendingflag == false); Ignored packet - %s"), sender->DbgGetClientInfo());
			break;
		}
		case OP_REASKACK:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_ReaskAck", sender, NULL, ip);
			if (sender && sender->UDPPacketPending()){
				CSafeMemFile data_in(packet, size);
				if ( sender->GetUDPVersion() > 3 )
				{
					sender->ProcessFileStatus(true, &data_in, sender->GetRequestFile());
				}
				uint16 nRank = data_in.ReadUInt16();
				sender->SetRemoteQueueFull(false);
				sender->UDPReaskACK(nRank);
				sender->AddAskedCountDown();
			}
			else if (sender != NULL)
				DebugLogError(_T("Received UDP Packet (OP_REASKACK) which was not requested (pendingflag == false); Ignored packet - %s"), sender->DbgGetClientInfo());
			
			break;
		}
		case OP_FILENOTFOUND:
		{
			theStats.AddDownDataOverheadFileRequest(size);
			CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_FileNotFound", sender, NULL, ip);
			if (sender && sender->UDPPacketPending()){
				sender->UDPReaskFNF(); // may delete 'sender'!
				sender = NULL;
			}
			else if (sender != NULL)
				DebugLogError(_T("Received UDP Packet (OP_FILENOTFOUND) which was not requested (pendingflag == false); Ignored packet - %s"), sender->DbgGetClientInfo());

			break;
		}
		case OP_PORTTEST:
		{
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_PortTest", NULL, NULL, ip);
			theStats.AddDownDataOverheadOther(size);
			if (size == 1){
				if (packet[0] == 0x12){
					bool ret = theApp.listensocket->SendPortTestReply('1', true);
					AddDebugLogLine(true, _T("UDP Portcheck packet arrived - ACK sent back (status=%i)"), ret);
				}
			}
			break;
		}
		case OP_DIRECTCALLBACKREQ:
		{
			if (thePrefs.GetDebugClientUDPLevel() > 0)
				DebugRecv("OP_DIRECTCALLBACKREQ", NULL, NULL, ip);
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
			// IPv6-TODO: Add IPv6 tracking
			if (ip.Type() == CAddress::IPv4 && !theApp.clientlist->AllowCalbackRequest(_ntohl(ip.ToIPv4()))){
#else // NEO: IP6 END
			if (!theApp.clientlist->AllowCalbackRequest(ip)){
#endif
				DebugLogWarning(_T("Ignored DirectCallback Request because this IP (%s) has sent too many request within a short time"), ipstr(ip));
				break;
			}
			// do we accept callbackrequests at all?
			if (Kademlia::CKademlia::IsRunning() && Kademlia::CKademlia::IsFirewalled())
			{
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
				// IPv6-TODO: Add IPv6 tracking
				if (ip.Type() == CAddress::IPv4)
					theApp.clientlist->AddTrackCallbackRequests(_ntohl(ip.ToIPv4()));
#else // NEO: IP6 END
				theApp.clientlist->AddTrackCallbackRequests(ip);
#endif
				CSafeMemFile data(packet, size);
				uint16 nRemoteTCPPort = data.ReadUInt16();
				uchar uchUserHash[16];
				data.ReadHash16(uchUserHash);
				uint8 byConnectOptions = data.ReadUInt8();
				CUpDownClient* pRequester = theApp.clientlist->FindClientByUserHash(uchUserHash, ip, nRemoteTCPPort);
				if (pRequester == NULL) {
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
					pRequester = new CUpDownClient(NULL, nRemoteTCPPort, ip, 0, 0);
#else // NEO: IP6 END
					pRequester = new CUpDownClient(NULL, nRemoteTCPPort, ip, 0, 0, true);
#endif
					pRequester->SetUserHash(uchUserHash);
					theApp.clientlist->AddClient(pRequester);
				}
				pRequester->SetConnectOptions(byConnectOptions, true, false);
				pRequester->SetDirectUDPCallbackSupport(false);
				pRequester->SetIP(ip);
				pRequester->SetUserPort(nRemoteTCPPort);
				DEBUG_ONLY( DebugLog(_T("Accepting incoming DirectCallbackRequest from %s"), pRequester->DbgGetClientInfo()) );
				pRequester->TryToConnect();
			}
			else
				DebugLogWarning(_T("Ignored DirectCallback Request because we do not accept DirectCall backs at all (%s)"), ipstr(ip));

			break;
		}
		default:
			theStats.AddDownDataOverheadOther(size);
			if (thePrefs.GetDebugClientUDPLevel() > 0)
			{
				CUpDownClient* sender = theApp.downloadqueue->GetDownloadClientByIP_UDP(ip, port, true);
				Debug(_T("Unknown client UDP packet: host=%s:%u (%s) opcode=0x%02x  size=%u\n"), ipstr(ip), port, sender ? sender->DbgGetClientInfo() : _T(""), opcode, size);
			}
			return false;
	}
	return true;
}

void CClientUDPSocket::OnSend(int nErrorCode){
	if (nErrorCode){
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket, error on send event: %s"), GetErrorMessage(nErrorCode, 1));
		return;
	}

// ZZ:UploadBandWithThrottler (UDP) -->
    sendLocker.Lock();
    m_bWouldBlock = false;

    if(!controlpacket_queue.IsEmpty()) {
        theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
    }
    sendLocker.Unlock();
// <-- ZZ:UploadBandWithThrottler (UDP)
}

SocketSentBytes CClientUDPSocket::SendControlData(uint32 maxNumberOfBytesToSend, uint32 /*minFragSize*/){ // ZZ:UploadBandWithThrottler (UDP)
// ZZ:UploadBandWithThrottler (UDP) -->
	// NOTE: *** This function is invoked from a *different* thread!
    sendLocker.Lock();

    uint32 sentBytes = 0;
// <-- ZZ:UploadBandWithThrottler (UDP)

	while (!controlpacket_queue.IsEmpty() && !IsBusy() && sentBytes < maxNumberOfBytesToSend){ // ZZ:UploadBandWithThrottler (UDP)
		UDPPack* cur_packet = controlpacket_queue.GetHead();
		if( GetTickCount() - cur_packet->dwTime < UDPMAXQUEUETIME )
		{
			uint32 nLen = cur_packet->packet->size+2;
			uchar* sendbuffer = new uchar[nLen];
			memcpy(sendbuffer,cur_packet->packet->GetUDPHeader(),2);
			memcpy(sendbuffer+2,cur_packet->packet->pBuffer,cur_packet->packet->size);
			
			if (cur_packet->bEncrypt && (theApp.GetPublicIP() > 0 || cur_packet->bKad)){
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
				nLen = EncryptSendClient(&sendbuffer, nLen, cur_packet->pachTargetClientHashORKadID, cur_packet->bKad,  cur_packet->nReceiverVerifyKey, (cur_packet->bKad ? Kademlia::CPrefs::GetUDPVerifyKey(_ntohl(cur_packet->IP.ToIPv4())) : (uint16)0), cur_packet->IP.Type() == CAddress::IPv6);
#else // NEO: IP6 END
				nLen = EncryptSendClient(&sendbuffer, nLen, cur_packet->pachTargetClientHashORKadID, cur_packet->bKad,  cur_packet->nReceiverVerifyKey, (cur_packet->bKad ? Kademlia::CPrefs::GetUDPVerifyKey(cur_packet->dwIP) : (uint16)0));
#endif
				//DEBUG_ONLY(  AddDebugLogLine(DLP_VERYLOW, false, _T("Sent obfuscated UDP packet to clientIP: %s, Kad: %s, ReceiverKey: %u"), ipstr(cur_packet->dwIP), cur_packet->bKad ? _T("Yes") : _T("No"), cur_packet->nReceiverVerifyKey) );
			}

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
            if (!SendTo((char*)sendbuffer, nLen, cur_packet->IP, cur_packet->nPort)){
#else // NEO: IP6 END
            if (!SendTo((char*)sendbuffer, nLen, cur_packet->dwIP, cur_packet->nPort)){
#endif
                sentBytes += nLen; // ZZ:UploadBandWithThrottler (UDP)

				controlpacket_queue.RemoveHead();
				delete cur_packet->packet;
				delete cur_packet;
            }
			delete[] sendbuffer;
		}
		else
		{
			controlpacket_queue.RemoveHead();
			delete cur_packet->packet;
			delete cur_packet;
		}
	}

// ZZ:UploadBandWithThrottler (UDP) -->
    if(!IsBusy() && !controlpacket_queue.IsEmpty()) {
        theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
    }
    sendLocker.Unlock();

    SocketSentBytes returnVal = { true, 0, sentBytes };
    return returnVal;
// <-- ZZ:UploadBandWithThrottler (UDP)
}

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
int CClientUDPSocket::SendTo(char* lpBuf,int nBufLen, CAddress IP, uint16 nPort){
#else // NEO: IP6 END
int CClientUDPSocket::SendTo(char* lpBuf,int nBufLen,uint32 dwIP, uint16 nPort){
#endif
	// NOTE: *** This function is invoked from a *different* thread!
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	//CAddress IP(_ntohl(dwIP));
	CAddress dwIP = IP;
	dwIP.Convert(CAddress::IPv6);
	SOCKADDR_IN6 sockAddr;
	int iSockAddrLen = sizeof(sockAddr);
	dwIP.ToSA((SOCKADDR*)&sockAddr, &iSockAddrLen, nPort);
	uint32 result = CAsyncSocket::SendTo(lpBuf, nBufLen, (SOCKADDR*)&sockAddr, sizeof sockAddr);
#else // NEO: IP6 END
	uint32 result = CAsyncSocket::SendTo(lpBuf,nBufLen,nPort,ipstr(dwIP));
#endif
	if (result == (uint32)SOCKET_ERROR){
		uint32 error = GetLastError();
		if (error == WSAEWOULDBLOCK){
			m_bWouldBlock = true;
			return -1;
		}
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Client UDP socket, failed to send data to %s:%u: %s"), ipstr(dwIP), nPort, GetErrorMessage(error, 1));
	}
	return 0;
}

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
bool CClientUDPSocket::SendPacket(Packet* packet, const CAddress& IP, uint16 nPort, bool bEncrypt, const uchar* pachTargetClientHashORKadID, bool bKad, uint32 nReceiverVerifyKey){
#else // NEO: IP6 END
bool CClientUDPSocket::SendPacket(Packet* packet, uint32 dwIP, uint16 nPort, bool bEncrypt, const uchar* pachTargetClientHashORKadID, bool bKad, uint32 nReceiverVerifyKey){
#endif
	UDPPack* newpending = new UDPPack;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	newpending->IP = IP;
#else // NEO: IP6 END
	newpending->dwIP = dwIP;
#endif
	newpending->nPort = nPort;
	newpending->packet = packet;
	newpending->dwTime = GetTickCount();
	newpending->bEncrypt = bEncrypt && (pachTargetClientHashORKadID != NULL || (bKad && nReceiverVerifyKey != 0));
	newpending->bKad = bKad;
	newpending->nReceiverVerifyKey = nReceiverVerifyKey;

#ifdef _DEBUG
	if (newpending->packet->size > UDP_KAD_MAXFRAGMENT)
		DebugLogWarning(_T("Sending UDP packet > UDP_KAD_MAXFRAGMENT, opcode: %X, size: %u"), packet->opcode, packet->size);
#endif

	if (newpending->bEncrypt && pachTargetClientHashORKadID != NULL)
		md4cpy(newpending->pachTargetClientHashORKadID, pachTargetClientHashORKadID);
	else
		md4clr(newpending->pachTargetClientHashORKadID);
// ZZ:UploadBandWithThrottler (UDP) -->
    sendLocker.Lock();
	controlpacket_queue.AddTail(newpending);
    sendLocker.Unlock();

    theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this);
	return true;
// <-- ZZ:UploadBandWithThrottler (UDP)
}

bool CClientUDPSocket::Create()
{
	bool ret = true;

	if (thePrefs.GetUDPPort())
	{
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
		CAsyncSocket::Socket(SOCK_DGRAM, FD_READ | FD_WRITE, 0, PF_INET6);

		int iOptVal = 0; // Enable this socket to accept IPv4 and IPv6 packets at the same time
		SetSockOpt(IPV6_V6ONLY, &iOptVal, sizeof iOptVal, IPPROTO_IPV6);

		sockaddr_in6 us;
		memset(&us, 0, sizeof(us));
        us.sin6_family = AF_INET6;
        us.sin6_port = htons(thePrefs.GetUDPPort());
        us.sin6_flowinfo = NULL;

        if(thePrefs.GetBindAddrA())
		{
			// Convert the IPv6 address to the sin6_addr structure
			struct sockaddr_storage ss;
			int sslen = sizeof(ss);
			if(WSAStringToAddressA((char*)thePrefs.GetBindAddrA(), AF_INET6, NULL, (struct sockaddr*)&ss, &sslen) == 0)
				us.sin6_addr = ((struct sockaddr_in6 *)&ss)->sin6_addr;
		}
		else
			us.sin6_addr = in6addr_any;

		ret = CAsyncSocket::Bind((const SOCKADDR*)&us, sizeof(us)) != FALSE;
#else // NEO: IP6 END
		ret = CAsyncSocket::Create(thePrefs.GetUDPPort(), SOCK_DGRAM, FD_READ | FD_WRITE, thePrefs.GetBindAddrW()) != FALSE;
#endif
		if (ret)
		{
			m_port = thePrefs.GetUDPPort();
			// the default socket size seems to be not enough for this UDP socket
			// because we tend to drop packets if several flow in at the same time
			int val = 64 * 1024;
			if (!SetSockOpt(SO_RCVBUF, &val, sizeof(val)))
				DebugLogError(_T("Failed to increase socket size on UDP socket"));
		}
	}

	if (ret)
		m_port = thePrefs.GetUDPPort();

	return ret;
}

bool CClientUDPSocket::Rebind()
{
	if (thePrefs.GetUDPPort() == m_port)
		return false;
	Close();
	return Create();
}
