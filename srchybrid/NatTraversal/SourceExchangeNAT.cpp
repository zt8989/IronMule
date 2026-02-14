/*
 * $Id: SourceExchangeNAT.cpp 11398 2009-03-17 11:00:27Z huby $
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
#include "../emule.h"

#include "SourceExchangeNAT.h"
#include "NatThread.h"

#include "../ListenSocket.h"
#include "../updownclient.h"
#include "../ClientList.h"
#include "../DownloadQueue.h"
#include "../SharedFileList.h"
#include "../KnownFile.h"
#include "../PartFile.h"

#include "../updownclient.h"

#ifdef _DEBUG_NAT
	extern void T_TRACE(char* fmt, ...);
#else
	#define T_TRACE
#endif

CSourceExchangeNAT::CSourceExchangeNAT()
{

}

CSourceExchangeNAT::~CSourceExchangeNAT()
{

}

bool CSourceExchangeNAT::ProcessUDPPacket(const BYTE* packet, UINT size, uint8 opcode, uint32 ip, uint16 port)
{
	try
	{
		switch (opcode)
		{
		// VC-SearchDream[2007-04-18]: For SourceExchange NAT Begin	
		case OP_UDPSENATREQ:
			{
				CSafeMemFile data(packet, size);
				uchar userhash[16];
				data.ReadHash16(userhash); // Read the NAT Target Client's UserHash

				T_TRACE("\nReceive UDP SourceExchange NAT Request , IP : %d Port : %d!\n", ip, port);

				CUpDownClient * pClient = theApp.clientlist->FindClientByUserHash(userhash);

				if (pClient)
				{
					data.ReadHash16(userhash); // Read the Request Client's UserHash
					uint32 con = data.ReadUInt32();

					try
					{
						if (!pClient->IsLowToLowClient() && (pClient->socket && pClient->socket->IsConnected()))	
						{
							//非LTL连接，且处于已连接状态
							CSafeMemFile data_out;
							data_out.WriteUInt32(ip);
							data_out.WriteUInt16(htons(port));
							data_out.WriteHash16(userhash);
							data_out.WriteUInt32(con);

							Packet* natreq = new Packet(&data_out, OP_EMULEPROT, OP_TCPSENATREQ);

							T_TRACE("\nThe Client is Exist and Send TCP SourceExchange NAT Request!\n");

							pClient->socket->SendPacket(natreq, true, true, 0, true);
						}
						else
						{
							//LTL连接或处于未连接状态
							uint16 uPort = htons(port);

							byte pack[1+1+4+2+16+4];
							pack[0]         = OP_EMULEPROT;
							pack[1]		    = OP_UDPTOUDPSENATREQ;
							memcpy(pack+2, &ip, 4);
							memcpy(pack+6, &uPort, 2);
							memcpy(pack+8, userhash, 16);
							memcpy(pack+24, &con, 4);

							T_TRACE("\nThe Client is Exist and Send UDP SourceExchange NAT Request!\n");

							SendUDPPacket(pClient->GetIP(), htons(pClient->GetUDPPort()), pack, 1+1+4+2+16+4, pClient);							
						}
					}
					catch(...)
					{
						return false;
					}	
				}

				break;
			}	
		case OP_UDPSENATACK:
			{
				CSafeMemFile data(packet, size);
				uchar userhash[16];
				data.ReadHash16(userhash); // Read the Request Client's UserHash

				T_TRACE("\nReceive UDP SourceExchange NAT Response , IP : %d Port : %d!\n", ip, port);

				CUpDownClient * pClient = theApp.clientlist->FindClientByUserHash(userhash);

				if (pClient)
				{
					data.ReadHash16(userhash); // Read the NAT Target Client's UserHash
					uint32 con = data.ReadUInt32();

					try
					{
						if (!pClient->IsLowToLowClient() && (pClient->socket && pClient->socket->IsConnected()))
						{
							CSafeMemFile data_out;
							data_out.WriteUInt32(ip);
							data_out.WriteUInt16(htons(port));
							data_out.WriteHash16(userhash);
							data_out.WriteUInt32(con);

							Packet* natack = new Packet(&data_out, OP_EMULEPROT, OP_TCPSENATACK);

							T_TRACE("\nThe Client is Exist and Send TCP SourceExchange NAT Response!\n");

							pClient->socket->SendPacket(natack, true, true, 0, true);
						}
						else 
						{
							uint16 uPort = htons(port);

							byte pack[1+1+4+2+16+4];
							pack[0]         = OP_EMULEPROT;
							pack[1]		    = OP_UDPTOUDPSENATACK;
							memcpy(pack+2, &ip, 4);
							memcpy(pack+6, &uPort, 2);
							memcpy(pack+8, userhash, 16);
							memcpy(pack+24, &con, 4);

							T_TRACE("\nThe Client is Exist and Send UDP SourceExchange NAT Response!\n");

							SendUDPPacket(pClient->GetIP(), htons(pClient->GetUDPPort()), pack, 1+1+4+2+16+4, pClient);
						}
					}
					catch(...)
					{
						return false;
					}
				}
				break;
			}
		case OP_UDPTOUDPSENATREQ:
			{
				T_TRACE("\nReceive UDP SourceExchange NAT Request!\n");

				CSafeMemFile data(packet, size);

				byte * natpack  = new byte[4+1+4+2+16+4];

				memset(natpack, 0, 4+1+4+2+16+4);

				natpack[4] = OP_NAT_SYNC;
				memcpy(natpack+5, packet, size);

				uint32 uUserIP  = data.ReadUInt32();
				uint16 uUdpPort = data.ReadUInt16(); 

				T_TRACE("\nIP:%d Port:%d\n", uUserIP, uUdpPort);

				uchar userhash[16];
				data.ReadHash16(userhash);

				uint32 con = data.ReadUInt32();

				byte * pack     = new byte[1+1+16+16+4];
				pack[0]         = OP_EMULEPROT;
				pack[1]		    = OP_UDPSENATACK;
				memcpy(pack+2, userhash, 16);
				memcpy(pack+18, thePrefs.GetUserHash(), 16);
				memcpy(pack+34, &con, 4);

				T_TRACE("\nSend UDP SourceExchange NAT Response!\n");

				CNatSocket::SendPacket(ip, htons(port), pack, 1+1+16+16+4);

				delete []pack;
				pack = NULL;

				if( theApp.natthread )
				theApp.natthread->ProcessPacket(natpack, 4+1+4+2+16+4, ip, htons(port));

				delete []natpack;
				natpack = NULL;

				break;
			}
		case OP_UDPTOUDPSENATACK:
			{
				CSafeMemFile data(packet, size);

				byte natpack[4+1+4+2+16+4];

				memset(natpack, 0, 4+1+4+2+16+4);

				natpack[4] = OP_NAT_SYNC;
				memcpy(natpack+5, packet, size);

				uint32 uUserIP  = data.ReadUInt32();
				uint16 uUdpPort = data.ReadUInt16(); 

				uchar userhash[16];
				data.ReadHash16(userhash);

				CUpDownClient* pClient = theApp.clientlist->FindClientByUserHash(userhash);

				if (pClient)
				{	
					pClient->SetIP(uUserIP);
					pClient->SetUDPPort(uUdpPort);

					T_TRACE("\nReceive UDP SourceExchange NAT Response!\n");

					if( theApp.natthread )
					theApp.natthread->ProcessPacket(natpack, 4+1+4+2+16+4, ip, htons(port));
				}

				break;
			}
		case OP_UDPREGISTER:
			{
				CSafeMemFile data(packet, size);

				uchar userhash[16];
				data.ReadHash16(userhash); // Read the Request Client's UserHash

				CUpDownClient* pClient = theApp.clientlist->FindClientByUserHash(userhash);

				T_TRACE("\nReceive Register From CSourceExchangeNAT::ProcessUDPPacket\n");

				if (pClient)
				{
					if (port != pClient->GetUDPPort())
					{
						pClient->SetUDPPort(port);
					}

					pClient->SetRegisterTime();
				}

				break;
			}
		case OP_UDPKEEPALIVE:
			{
				CUpDownClient* pClient = theApp.clientlist->FindClientByIP_UDP(ip, port);

				T_TRACE("\nReceive KeepALive From CSourceExchangeNAT::ProcessUDPPacket\n");

				if (pClient)
				{
					pClient->SetReceiveALiveTime();
				}

				break;
			}
			// VC-SearchDream[2007-04-18]: For SourceExchange NAT End
		case OP_SECALLBACK:
			{
				CSafeMemFile data(packet, size);

				uchar fileid[16];
				data.ReadHash16(fileid);

				CKnownFile* reqfile;

				if ( (reqfile = theApp.sharedfiles->GetFileByID(fileid)) == NULL )
				{
					if ( (reqfile = theApp.downloadqueue->GetFileByID(fileid)) == NULL)
					{
						/*socket->client->CheckFailedFileIdReqs(fileid);*/
						break;
					}
				}

				uint32 ip  = data.ReadUInt32();
				uint16 tcp = data.ReadUInt16();

				CUpDownClient* callback;

				callback = theApp.clientlist->FindClientByIP(ntohl(ip), tcp);

				if ( callback == NULL )
				{
					callback = new CUpDownClient(NULL,tcp,ip,0,0, true);
					theApp.clientlist->AddClient(callback);
				}

				callback->TryToConnect(true);

				break;
			}
		default:
			{
				return true;
			}
		}
	}
	catch(...)
	{
		return false; // The Process is Over Although Failure
	}

	return false;
}

bool CSourceExchangeNAT::ProcessTCPPacket(const BYTE* packet, uint32 size, UINT opcode, UINT /*uRawSize*/, CClientReqSocket * socket)
{
	try
	{
		switch (opcode)
		{
		case OP_TCPSENATREQ:
			{
				T_TRACE("\nReceive TCP SourceExchange NAT Request!\n");

				CSafeMemFile data(packet, size);

				byte * natpack  = new byte[4+1+4+2+16+4];

				memset(natpack, 0, 4+1+4+2+16+4);

				natpack[4] = OP_NAT_SYNC;
				memcpy(natpack+5, packet, size);

				uint32 uUserIP  = data.ReadUInt32();
				uint16 uUdpPort = data.ReadUInt16(); 

				T_TRACE("\nIP:%d Port:%d\n", uUserIP, uUdpPort);

				uchar userhash[16];
				data.ReadHash16(userhash);

				uint32 con = data.ReadUInt32();

				byte * pack     = new byte[1+1+16+16+4];
				pack[0]         = OP_EMULEPROT;
				pack[1]		    = OP_UDPSENATACK;
				memcpy(pack+2, userhash, 16);
				memcpy(pack+18, thePrefs.GetUserHash(), 16);
				memcpy(pack+34, &con, 4);

				T_TRACE("\nSend UDP SourceExchange NAT Response!\n");

				if (!socket->client)
				{
					return false; // VC-SearchDream[2007-04-18]: 
				}

				CNatSocket::SendPacket(socket->client->GetIP(), htons(socket->client->GetUDPPort()), pack, 1+1+16+16+4);

				delete []pack;
				pack = NULL;

				if( theApp.natthread )
				theApp.natthread->ProcessPacket(natpack, 4+1+4+2+16+4, socket->client->GetIP(), htons(socket->client->GetUDPPort()));

				delete []natpack;
				natpack = NULL;

				break;
			}
		case OP_TCPSENATACK:
			{
				CSafeMemFile data(packet, size);

				byte natpack[4+1+4+2+16+4];

				memset(natpack, 0, 4+1+4+2+16+4);

				natpack[4] = OP_NAT_SYNC;
				memcpy(natpack+5, packet, size);

				uint32 uUserIP  = data.ReadUInt32();
				uint16 uUdpPort = data.ReadUInt16(); 

				uchar userhash[16];
				data.ReadHash16(userhash);

				CUpDownClient* pClient = theApp.clientlist->FindClientByUserHash(userhash);

				if (pClient)
				{	
					pClient->SetIP(uUserIP);
					pClient->SetUDPPort(uUdpPort);

					T_TRACE("\nReceive TCP SourceExchange NAT Response!\n");

					if( theApp.natthread )
					theApp.natthread->ProcessPacket(natpack, 4+1+4+2+16+4, socket->client->GetIP(), htons(socket->client->GetUDPPort()));
				}

				break;
			}
		case OP_TCPSECALLBACKREQ:
			{
				CSafeMemFile data(packet, size);
				uchar userhash[16];
				data.ReadHash16(userhash); // Read the Call Back Target Client's UserHash

				CUpDownClient * pClient = theApp.clientlist->FindClientByUserHash(userhash);

				if (pClient)
				{			
					if (!pClient->IsLowToLowClient() && (pClient->socket && pClient->socket->IsConnected()))
					{
						CSafeMemFile fileIO(16+6);
						fileIO.WriteHash16(socket->client->GetUploadFileID());
						fileIO.WriteUInt32(socket->client->GetIP());
						fileIO.WriteUInt16(socket->client->GetUserPort());

						Packet* pPacket = new Packet(&fileIO, OP_EMULEPROT, OP_SECALLBACK);

						pClient->socket->SendPacket(pPacket, true, true, 0, true);
					}
					else
					{
						byte pack[1+1+16+6];
						pack[0]         = OP_EMULEPROT;
						pack[1]		    = OP_SECALLBACK;

						uint32 ip   = socket->client->GetIP();
						uint16 port = socket->client->GetUserPort();

						memcpy(pack+2,  socket->client->GetUploadFileID(), 16);
						memcpy(pack+18, &ip, 4);
						memcpy(pack+22, &port, 2);

						SendUDPPacket(pClient->GetIP(), htons(pClient->GetUDPPort()), pack, 1+1+16+6, pClient);
					}
				}

				break;
			}
		case OP_SECALLBACK:
			{
				CSafeMemFile data(packet, size);

				uchar fileid[16];
				data.ReadHash16(fileid);

				CKnownFile* reqfile;

				if ( (reqfile = theApp.sharedfiles->GetFileByID(fileid)) == NULL )
				{
					if ( (reqfile = theApp.downloadqueue->GetFileByID(fileid)) == NULL)
					{
						socket->client->CheckFailedFileIdReqs(fileid);
						break;
					}
				}

				uint32 ip  = data.ReadUInt32();
				uint16 tcp = data.ReadUInt16();
				
				CUpDownClient* callback;
				
				callback = theApp.clientlist->FindClientByIP(ntohl(ip), tcp);
				
				if ( callback == NULL )
				{
					callback = new CUpDownClient(NULL,tcp,ip,0,0, true);
					theApp.clientlist->AddClient(callback);
				}

				callback->TryToConnect(true);

				break;
			}
		default:
			{
				return true;
			}
		}
	}
	catch(...)
	{
		return false; // The Process is Over Although Failure
	}

	return false;
}

void CSourceExchangeNAT::CheckUDPTunnel(CUpDownClient * pClient)
{
	if (!pClient)
	{
		return;
	}

	if (!pClient->IsSupportTraverse())
	{
		return;
	}

	if (!theApp.IsFirewalled() && !pClient->HasLowID())
	{
		return;
	}

	if (pClient->IsLowToLowClient())
	{
		return;
	}

	if (pClient->socket && pClient->socket->IsConnected())
	{
		return;
	}

	CheckConnection(pClient);

	CheckForTimeOut(pClient);
}

void CSourceExchangeNAT::CheckConnection(CUpDownClient * pClient)
{
	if(time(NULL) - pClient->m_dwReceiveKeepALiveTime > 4 * TM_KEEPALIVE)
	{
		pClient->m_nUDPState = UDP_DISCONNECT;
	}
}

void CSourceExchangeNAT::CheckForTimeOut(CUpDownClient * pClient)
{
	if (pClient->m_nUDPState == UDP_DISCONNECT)
	{
		return;
	}

	if(time(NULL) - pClient->m_dwRegisterTime > 60 * 10)
	{
		byte pack[1+1+16];
		pack[0]         = OP_EMULEPROT;
		pack[1]		    = OP_UDPREGISTER;
		memcpy(pack+2, pClient->GetUserHash(), 16);

		SendUDPPacket(pClient->GetIP(), htons(pClient->GetUDPPort()), pack, 1+1+16, pClient);

		T_TRACE("\nSend Register From CSourceExchangeNAT::CheckForTimeOut.\n");

		pClient->m_dwRegisterTime		= time(NULL);
		pClient->m_dwSendKeepALiveTime	= time(NULL);

		return;
	}

	if(time(NULL) - pClient->m_dwSendKeepALiveTime > TM_KEEPALIVE)
	{
		byte pack[1+1];
		pack[0]         = OP_EMULEPROT;
		pack[1]		    = OP_UDPKEEPALIVE;

		SendUDPPacket(pClient->GetIP(), htons(pClient->GetUDPPort()), pack, 1+1, pClient);

		T_TRACE("\nSend KeepALive From CSourceExchangeNAT::CheckForTimeOut.\n");

		pClient->m_dwSendKeepALiveTime = time(NULL);

		return;
	}
}

bool CSourceExchangeNAT::SendUDPPacket(DWORD ip, WORD port, const uchar * data, int len, CUpDownClient * pClient)
{
	if (!pClient)
	{
		return false;
	}

	if (pClient->IsLowToLowClient())
	{
		CNatSocket::SendPacket(ip, port, data, len);
		return true;
	}

	if (pClient->m_nUDPState == UDP_CONNECTED)
	{
		CNatSocket::SendPacket(ip, port, data, len);
		return true;
	}

	return false;
}


