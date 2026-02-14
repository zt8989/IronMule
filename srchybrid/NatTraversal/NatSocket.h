/*
 * $Id: NatSocket.h 4789 2008-02-14 08:59:23Z fengwen $
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

#include <set>
//#include "emule.h"
#include "Preferences.h"
#include "Log.h"
#include "AsyncSocketEx.h"
#include "EMSocket.h"
#include "CLientUDPSocket.h"
#include "Packets.h"
#include "opcodes.h"

////////////////////////////////////////////////////////////////////////////

#define OP_VC_NAT_HEADER		0xf1

#define OP_NAT_SYNC				0xE1
#define OP_NAT_PING				0xE2

#define OP_NAT_REGISTER			0xE4
#define OP_NAT_FAILED			0xE5


#define OP_NAT_REPING			0xE8
#define OP_NAT_SYNC2			0xE9

#define OP_NAT_DATA				0xEA	// data segment with a part of the stream
#define OP_NAT_ACK				0xEB	// data segment acknowledgement

#define OP_NAT_RST				0xEF	// connection closed

////////////////////////////////////////////////////////////////////////////
// Nat config packet tags
#define	NTT_VERSION				0x01
#define	NTT_MSS_SIZE			0x02
#define	NTT_NAT_TYPE			0x11
#define	NTT_FIX_PORT			0x12
#define	NTT_BUDDY_ID			0xB0
#define	NTT_BUDDY_IP			0xB1
#define	NTT_BUDDY_PORT			0xB2

#define CT_NAT_TUNNELING		0xE1 // NEO: NATT - [NatTraversal]
#define CT_NEO_FEATURES			'N' // NEO: NMP - [NeoModProt]
#define CT_EMULE_BUDDYID		0xE2 // NEO: NATS - [NatSupport]

const DWORD TM_KEEPALIVE	= 20;  // 20 seconds

#include "../AsyncSocketEx.h"

using namespace std;

class CDataHandler
{
public:
	virtual int SendPacket(DWORD ip, WORD port, uchar opcode, const uchar * data, int len) = NULL;
};

#pragma pack(1)
struct sUserModeTCPConfig{
	sUserModeTCPConfig(uint32 IP, uint16 Port)
	{
		TargetIP = IP;
		TargetPort = Port;
		Version = 0;
		MaxSegmentSize = 0;
		MaxUploadBufferSize = 0;
		MaxDownloadBufferSize = 0;
	}
	uint32	TargetIP;
	uint16	TargetPort;
	uint8	Version;
	uint32	MaxSegmentSize;
	uint32	MaxUploadBufferSize;
	uint32	MaxDownloadBufferSize;
};
#pragma pack()

#pragma pack(1)
struct sTransferBufferEntry{
	sTransferBufferEntry(uint32 size, const BYTE* data, uint32 Nr)
	{
		uSize = size;
		pBuffer = new BYTE[uSize+1];
		memcpy(pBuffer,data,size);

		uSequenceNr = Nr;
		uSendCount = 0;
		uSendTime = 0;
	}
	~sTransferBufferEntry() { delete [] pBuffer; }

	BYTE*	pBuffer;		// buffered data
	uint32	uSize;			// data size, <= max segment size
	uint32	uSequenceNr;	// segment sequence number
	uint8	uSendCount;		// we will not try resending the packet for ever just a few times
	uint32	uSendTime;		// time when we send the packet for the RTT and resend timeout
};

#pragma pack()

typedef CRBMap<uint32,sTransferBufferEntry*> TransferBuffer;

///////////////////////////////////////////////////////////////////////////////
// CNatSocket

class CNatSocket// : public CAbstractSocket
{
	friend class CNatThread;
public:
	enum TraversalType
	{
		Traversal_none,
		Traversal_bysvr,
		Traversal_bybuddy,
		Traversal_byexchangesource
	};
	TraversalType m_TraversalType;

	CNatSocket(CAsyncSocketEx* Parent);
	virtual ~CNatSocket();

	// set new User Mode TCP Sonfigurations
	void SetConfig(sUserModeTCPConfig* UserModeTCPConfig);
	bool IsConfig()	{return m_UserModeTCPConfig != NULL;}

	//Notifies a listening socket that it can accept pending connection requests by calling Accept.
	//virtual void OnAccept(int /*nErrorCode*/) {ASSERT(0);} // this sockets do not listen

	//Notifies a socket that the socket connected to it has closed.
	virtual void OnClose(int nErrorCode) {if(m_Parent) m_Parent->OnClose(nErrorCode);}

	//Notifies a connecting socket that the connection attempt is complete, whether successfully or in error.
	virtual void OnConnect(int nErrorCode) {if(m_Parent) m_Parent->OnConnect(nErrorCode);}

	//Notifies a listening socket that there is data to be retrieved by calling Receive.
	virtual void OnReceive(int nErrorCode) {if(m_Parent) m_Parent->OnReceive(nErrorCode);}

	//Notifies a socket that it can send data by calling Send.
	virtual void OnSend(int nErrorCode) {if(m_Parent) m_Parent->OnSend(nErrorCode);}

	virtual int SendPacket(uchar opcode, const uchar * data, int len);

	//Operations
	//----------
	uchar * GetUserHash()
	{
		return m_UserHash;
	}
#ifdef _DEBUG
	void TestBuffer();
#endif
	//Establishes a connection to a peer socket.
	virtual BOOL Connect(LPCSTR /*lpszHostAddress*/, UINT /*nHostPort*/)		{ ASSERT(0); return 0; }
	virtual BOOL Connect(const SOCKADDR* /*lpSockAddr*/, int /*nSockAddrLen*/)  { ASSERT(0); return 0; }

	//Receives data from the socket.
	int Receive(void* lpBuf, int nBufLen, int nFlags = 0);

	//Sends data to a connected socket.
	virtual int Send(const void* lpBuf, int nBufLen, int nFlags = 0);

	uint32 GetTargetIP() {return m_UserModeTCPConfig ? m_UserModeTCPConfig->TargetIP : 0;}
	uint16 GetTargetPort() {return m_UserModeTCPConfig ? m_UserModeTCPConfig->TargetPort : 0;}
	void SetTargetAddr(DWORD ip, WORD port)
	{
		if(m_UserModeTCPConfig)
		{
			m_UserModeTCPConfig->TargetIP = ip;
			m_UserModeTCPConfig->TargetPort = port;
		}
	}

	DWORD GetTimeout()
	{
		return m_dwTimeToCheck;
	}
	CAsyncSocketEx * GetParent() const
	{
		return m_Parent;
	}
	bool ProcessDataPacket(const BYTE* packet, UINT size);
	void ProcessAckPacket(const BYTE* packet, UINT size);

	DWORD m_dwConnAskNumber;
	void DumpData();
	void RenewNatSock();

	static int SendPacket(DWORD ip, WORD port, uchar opcode, const uchar * data, int len);
	static int SendPacket(DWORD ip, WORD port, const uchar * data, int len);
protected:
	DWORD m_dwSendKeepalive, m_dwRecvKeepalive;
	DWORD m_dwTimeToCheck;
	void CheckForTimeOut();

	sUserModeTCPConfig* m_UserModeTCPConfig; // our general settings

#ifdef _DEBUG
	virtual void AssertValid() const { }
	virtual void Dump(CDumpContext& /*dc*/) const { }
#endif

private:

	void SendBufferedSegment(sTransferBufferEntry* BufferEntry);
	void SendAckPacket(uint32 uSequenceNr);
	
	//UpStream
	//--------
#if defined(REGULAR_TCP)
	uint8  m_uDuplicatedACKCount; // count dupplicated ack's if we recive 3 it means we must resend the next segment (Fast Retransmission)
#endif

	uint32 m_uPendingWindowSize; // the amount of segments currently being on the network

	uint32 m_uLastSentSequenceNr; // number of last sent segment
	uint32 m_uUploadBufferSize;
	TransferBuffer m_UploadBuffer;	// Note: unfortunatly the CRBMap does not have a FindFirstKeyBefoure function 
									//	so for the uplaod buffer I reverse the map direction by using mapkey = UINT_MAX-key ;)

	//DowmStream
	//----------
	uint32 m_uLastAcknowledgeSequenceNr; // last sequence number completly pased to the CEMsocket
	uint32 m_uMaxSendSequenceNr;
	uint32 m_uLastRecvSequenceNr;
#if defined(REGULAR_TCP)
	bool   m_bSegmentMissing;
#endif
	uint32 m_uCurrentSegmentPosition;
	uint32 m_uDownloadBufferSize;
	bool   m_bReNotifyWindowSize; 
	TransferBuffer m_DownloadBuffer;

	//Attributes
	uint8  m_ShutDown;

	CAsyncSocketEx * m_Parent;
	uchar m_UserHash[16];

	//VC-fengwen on 2008/01/03 <begin> : 加入拥塞处理解决clients断网问题。
	enum{MAX_UPLOAD_SEGS = 36};
	enum{DEF_MSS = 512, MIN_RTO = 25, DUPACKS = 3};

	struct{
		uint32	una;	/* First unacknowledged sequence number */
		uint32	ptr;	/* Working transmission pointer */
		int		wnd;	/* Other end's offered receive window */
	} m_snd;
	set<uint32>	m_unackSet; //unacknowledged sequences;

	int		m_cwnd;			// Congestion window
	int		m_ssthresh;		// Slow-start threshold
	int		m_cntNotFirstUna;	//the count of received acks which are not the first unacknowledged sequence number;


	int		m_backoff;		/* Backoff interval */
	int		m_srtt;			/* Smoothed round trip time, milliseconds */
	int		m_mdev;			/* Mean deviation, milliseconds */ //衡量rtt的变化速度。

	void Output();
	int Backoff(int n)
	{
		if(n > 31) n = 31;	/* Prevent truncation to zero */
		return 1L << n;	/* Binary exponential back off */
	}
	int	GetFirstUna();	//找到第一个unacknowledge的Sequence
	//VC-fengwen on 2008/01/03 <end> : 加入拥塞处理解决clients断网问题。

};

