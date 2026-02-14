/*
 * $Id: NatSocket.cpp 11398 2009-03-17 11:00:27Z huby $
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
#include "emule.h"
#include "NatSocket.h"
#include "UploadQueue.h"
#include "NatThread.h"
#include "..\UserMsgs.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const int MAX_BUF_SIZE = 8 * 1024;
const int MAX_CHECK_TIME = 1721;

#ifdef _DEBUG_NAT
inline void T_TRACE(char* fmt, ...)
{
	va_list argptr;
	char bufferline[1024];
	va_start(argptr, fmt);
	_vsnprintf(bufferline, 1023, fmt, argptr);
	va_end(argptr);

	char /*osDate[30],*/osTime[30]; 
	_strtime( osTime );
	//_strdate( osDate );

	char tempf[1024+512]; 
	_snprintf(tempf,1024+511,"###  %08d: %s\n", /*osDate, */GetTickCount(), bufferline);
	OutputDebugStringA(tempf);
}
#else
#define T_TRACE
#endif

int CNatSocket::SendPacket(DWORD ip, WORD port, const uchar * data, int len)
{
	SOCKADDR_IN addr;
	addr.sin_addr.s_addr=ip;
	addr.sin_family=AF_INET;
	addr.sin_port = port;
	return sendto(theApp.clientudp->m_hSocket, (const char*)data, len, 0, (SOCKADDR*)&addr, sizeof(addr));
}

int CNatSocket::SendPacket(DWORD ip, WORD port, uchar opcode, const uchar * data, int len)
{
	Packet pack(opcode, len, OP_VC_NAT_HEADER,false);
	if(len>0 && data) memcpy(pack.pBuffer, data, len);

	SOCKADDR_IN addr;
	addr.sin_addr.s_addr=ip;
	addr.sin_family=AF_INET;
	addr.sin_port = port;
	return sendto(theApp.clientudp->m_hSocket,pack.GetPacket(), pack.GetRealPacketSize(),
		0, (SOCKADDR*)&addr, sizeof(addr));
}

CNatSocket::CNatSocket(CAsyncSocketEx* Parent) : m_Parent(Parent)
{
	m_UserModeTCPConfig = NULL;

#if defined(REGULAR_TCP)
	m_uDuplicatedACKCount = 0;
#endif

	m_uPendingWindowSize = 0;

	m_uLastSentSequenceNr = 0;
	m_uLastRecvSequenceNr = 0;
	m_uUploadBufferSize = 0;

	// DownStream
	m_uLastAcknowledgeSequenceNr = 0;
#if defined(REGULAR_TCP)
	m_bSegmentMissing = false;
#endif
	m_uCurrentSegmentPosition = 0;
	m_uDownloadBufferSize = 0;
	m_bReNotifyWindowSize = false;

	// other
	m_ShutDown = 0;

	m_dwSendKeepalive = m_dwRecvKeepalive =0;

	m_uMaxSendSequenceNr = 0;

	m_dwConnAskNumber = 0;
	m_dwRecvKeepalive = time(NULL);

	m_dwTimeToCheck = MAX_CHECK_TIME;

	m_TraversalType = Traversal_none;

	m_snd.una		= 1;
	m_snd.ptr		= 1;
	m_snd.wnd		= MAX_BUF_SIZE;

	m_cwnd			= DEF_MSS;
	m_ssthresh		= 65535;
	m_cntNotFirstUna	= 0;
	
	m_backoff		= 0;
	m_srtt			= 0;
	m_mdev			= 3;
}

/**
* The destructor deletes the socket and remove's it from the nat_socket_list.
*/
CNatSocket::~CNatSocket() 
{
	_AddDebugLogLine(false, _T("->%s: Destroy NAT Socket of %02X%02X%02X%02X\n"), __FUNCTION__, m_UserHash[0],m_UserHash[1],m_UserHash[2],m_UserHash[3]);

	// remove socket from nat socket list
//	theApp.clientudp->RemoveNatSocket(this);

	//m_natwnd.DestroyWindow();

//	m_UpLocker.Lock();
	for(POSITION pos = m_UploadBuffer.GetTailPosition();pos;)
		delete m_UploadBuffer.GetPrev(pos)->m_value;
	m_UploadBuffer.RemoveAll();
//	m_UpLocker.Unlock();

//	m_DownLocker.Lock();
	for(POSITION pos = m_DownloadBuffer.GetTailPosition();pos;)
		delete m_DownloadBuffer.GetPrev(pos)->m_value;
	m_DownloadBuffer.RemoveAll();
//	m_DownLocker.Unlock();

	delete m_UserModeTCPConfig;

	//if(m_Parent)
	//	m_Parent->OnClose(0);
}

/**
* SetConfig removes the old socket configuration and replace it with a new one
*   but usualy this function should be called only once.
* The new settings will be verifyed and unspecifyed values will be set to default.
*
* @param UserModeTCPConfig: pointer on the new configuration structure.
*/
void CNatSocket::SetConfig(sUserModeTCPConfig* UserModeTCPConfig)
{
	if(m_UserModeTCPConfig)
		delete m_UserModeTCPConfig;
	m_UserModeTCPConfig = UserModeTCPConfig;

	ASSERT(m_UserModeTCPConfig->TargetIP && m_UserModeTCPConfig->TargetPort);

	if( m_UserModeTCPConfig->MaxSegmentSize == 0 // this information is obtional it musn't be send by the remote cleint
	 || m_UserModeTCPConfig->MaxSegmentSize > MAXFRAGSIZE) // we always take the smaller one
		m_UserModeTCPConfig->MaxSegmentSize = MAXFRAGSIZE;

	m_UserModeTCPConfig->MaxDownloadBufferSize = 16*1024;
	m_UserModeTCPConfig->MaxUploadBufferSize = 8*1024;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Upload implementation //
///////////////////////////

/**
* Send is calles from CEMSocket like for a usual TCP socket,
*   The function copyes the data to the socket intern upload buffer and splits tham in segments,
*   every segment gets an uniqie segment number.
*
* Synchronisation note: This function locks the Uplaod Buffer Mutex.
*
* @param lpBuf: pointer on the data buffer to read.
*
* @param nBufLen: buffer length.
*
* @param nFlags: unused yet.
*/
int CNatSocket::Send(const void* lpBuf, int nBufLen, int /*nFlags*/)
{
	// NOTE: *** This function is invoked from a *different* thread!
	//T_TRACE("%s: used buffer size=%d, max size=%d\n", __FUNCTION__,
	//	m_uUploadBufferSize + (unsigned)nBufLen,
	//	MAX_BUF_SIZE);
	ASSERT(m_UserModeTCPConfig);

	if(m_UserModeTCPConfig == NULL ||
		m_UploadBuffer.GetCount()> MAX_UPLOAD_SEGS ||
		m_dwConnAskNumber==0)
	{
		SetLastError(WSAEWOULDBLOCK);
		//T_TRACE("send buffer overflow");
		return SOCKET_ERROR;
	}

	//if(MAX_BUF_SIZE < m_uUploadBufferSize) return 0;
	uint32 toSend = nBufLen;//min((unsigned)nBufLen, m_UserModeTCPConfig->MaxUploadBufferSize - m_uUploadBufferSize);
	
	//m_UpLocker.Lock();

	CList<sTransferBufferEntry*, sTransferBufferEntry*> EntryLstToSend;
	uint32 Sent = 0;
	while(toSend > Sent) 
	{
		uint32 uSequenceNr;
		sTransferBufferEntry* BufferEntry;
		POSITION pos = m_UploadBuffer.GetTailPosition();//.GetHeadPosition();	// Note: on a CRBMap this points always on the object with the lowest key, 
															//		 bu becouse we rever the map keys (mapkey = UINT_MAX-key) 
		if(pos)
		{ 											//		 it points always on the entry with the highest Sequence Number
			BufferEntry = m_UploadBuffer.GetValueAt(pos);
			if(BufferEntry->uSize < m_UserModeTCPConfig->MaxSegmentSize && BufferEntry->uSendCount == 0)
			{ 
				// if this segment is not full and wsn't already sent, fill it up
				uSequenceNr = 0;
			}
			else
			{ 
				// create a new segment
				uSequenceNr = ++m_uMaxSendSequenceNr;
				BufferEntry = NULL;
			}
		}
		else
		{
			// no pending segments
			uSequenceNr = ++m_uMaxSendSequenceNr;
			BufferEntry = NULL;
		}

		// We Split the data into segments
		uint32 Size = min((toSend - Sent),m_UserModeTCPConfig->MaxSegmentSize);
		try
		{
			if(BufferEntry == NULL)
			{
				BufferEntry = new sTransferBufferEntry(Size, (const BYTE*)lpBuf+Sent, uSequenceNr);
				m_UploadBuffer.SetAt(uSequenceNr, BufferEntry);
			}
			else
			{ 
				// to save overhead we try to send only full segments when there are some not full bufferes
				Size = min(Size, (uint32)abs(int(m_UserModeTCPConfig->MaxSegmentSize - BufferEntry->uSize)));

				uint32 tmpSize = BufferEntry->uSize;
				BYTE* tmpBuffer = BufferEntry->pBuffer;
				BufferEntry->uSize += Size;
				BufferEntry->pBuffer = new BYTE[BufferEntry->uSize];
				memcpy(BufferEntry->pBuffer,tmpBuffer,tmpSize);
				memcpy((BYTE*)BufferEntry->pBuffer+tmpSize,(const BYTE*)lpBuf+Sent,Size);
				delete [] tmpBuffer;
			}
		}
		catch(...)
		{
			break;
		}

		EntryLstToSend.AddTail(BufferEntry);

		Sent += Size;

		// increment our send buffer size
		m_uUploadBufferSize += Size;
#ifdef _DEBUG
		TestBuffer();
#endif
	}

	Output();

	return Sent; // return the number if bytes we actualy tooken
}

void CNatSocket::SendBufferedSegment(sTransferBufferEntry* BufferEntry)
{
	// NOTE: This function is invoked from a *different* thread! But all places where it is called are (and must be) locked already

/*	T_TRACE("%s: Segment Size=%u; uSequenceNr=%u, ConnAck=%d",__FUNCTION__,
		BufferEntry ? BufferEntry->uSize : 0, BufferEntry ? BufferEntry->uSequenceNr : 0,
		m_dwConnAskNumber);
*/
	if(m_ShutDown & 0x02)
	{
		return; // shocket is shuting down
	}

	uchar *pBuffer=NULL;
	int size=0;

	if(BufferEntry)
	{
		//VC-fengwen on 2008/01/04 <begin> :
		if (0 == BufferEntry->uSendCount)
		{
			m_uPendingWindowSize += BufferEntry->uSize;
			m_unackSet.insert(BufferEntry->uSequenceNr);
		}
		//VC-fengwen on 2008/01/04 <end> :

		BufferEntry->uSendCount++;
		BufferEntry->uSendTime = ::GetTickCount();

		size = BufferEntry->uSize + 4+4;// segment size + 4 bytes sequence number, there are also 2 bytes ed2k opcodes thiere are irrleevant here
		pBuffer = new uchar[size];

		PokeUInt32(pBuffer, m_dwConnAskNumber);
		PokeUInt32(pBuffer+4, BufferEntry->uSequenceNr); // segment sequence number
		// Note: we don't need to write the length as the UDP protocol already take care about the size
		memcpy(pBuffer+8,BufferEntry->pBuffer,BufferEntry->uSize);
	}
	else // if the last recived Advertised Window size is 0 and we have datas in buffer we ping with empty segments to get a new window size
			// Note: regular TCP sendy a minimal data segment != 0 expecting it to be dropped is window is still 0
	{
		size = 4+4;
		pBuffer = new uchar[8];

		PokeUInt32(pBuffer, 0);
		PokeUInt32(pBuffer+4, 0);
	}

	// send packet

	if(size && pBuffer)
	{
		SendPacket(OP_NAT_DATA, pBuffer, size);

		//T_TRACE("Window Size %d", m_snd.wnd);
	}

	delete [] pBuffer;
}

#ifdef _DEBUG
void CNatSocket::TestBuffer()
{
	int total = 0;
	POSITION pos= m_UploadBuffer.GetHeadPosition();
	while(pos)
	{
		total+= m_UploadBuffer.GetNextValue(pos)->uSize;
	}
	if((int)m_uUploadBufferSize!=total)
	{
		__asm int 3
	}
}

#endif

/**
* ProcessAckPacket is colled by the udp socket (main thread) when an NAT ACK packet was recived.
*   The function free's the acknowledged buffer space and calls TryToSend to put new segments on the network.
*    In the old TCP implementation it also handles the fast Retransmission
*   The ACK may have the uSequenceNr = 0 this means it's only an answer on a ping whitch privides us a new m_snd.wnd > 0
*
* @param packet: pointer to the recived packet buffer.
*
* @param size: recived packet buffer size.
*/
void CNatSocket::ProcessAckPacket(const BYTE* packet, UINT size)
{
	m_dwRecvKeepalive = time(NULL);
	ASSERT(m_UserModeTCPConfig);

	ASSERT(size == 8);

	// read the sequence number of the last acknowledge segment
	uint32 uSequenceNr = PeekUInt32(packet); 

	// read the actual Advertised Window size (Incoming window)
	m_snd.wnd = PeekUInt32(packet+4);

//	T_TRACE("%s: uSequenceNr=%u",__FUNCTION__, uSequenceNr);

	sTransferBufferEntry* BufferEntry;
	if(uSequenceNr == 0)
	{
		// Note: ACK's with sequence number 0 indicates us that the m_snd.wnd of the remote side is open again
		// the remote side may sendit without being asked or when it recives a data segment with 0 data size
		//ASSERT(m_snd.wnd >= 0);
	}
	else if(m_UploadBuffer.Lookup(/*UINT_MAX-*/uSequenceNr,BufferEntry))
	{
		// --------------------------
		// Packet Timing Calculations
		// --------------------------
		ASSERT(BufferEntry->uSendCount);

		m_UploadBuffer.RemoveKey(uSequenceNr);

		// data have left the network
		m_uPendingWindowSize -= BufferEntry->uSize; //m_UserModeTCPConfig->MaxSegmentSize;

		// remove packet from buffer
		m_uUploadBufferSize -= BufferEntry->uSize;

		m_unackSet.erase(uSequenceNr);	//VC-fengwen on 2008/01/04 

		//VC-fengwen on 2008/01/03 <begin> : increase the size of congestion window
		int mss = m_UserModeTCPConfig?m_UserModeTCPConfig->MaxSegmentSize:DEF_MSS;
		if (m_cwnd < m_ssthresh)
			m_cwnd += mss;
		else
			m_cwnd += mss*mss/m_cwnd;
		//VC-fengwen on 2008/01/03 <end> : increase the size of congestion window

		if(BufferEntry->uSendCount<2)
		{
			//VC-fengwen on 2008/01/04 <begin> : 按tcp方式计算rto
			m_backoff = 0;

			int rtt = GetTickCount()-BufferEntry->uSendTime;
			int abserr = (rtt > m_srtt) ? rtt - m_srtt : m_srtt - rtt;
			m_srtt = (7*m_srtt + rtt) >> 3;
			m_mdev = (3*m_mdev + abserr) >> 2;

			m_dwTimeToCheck = m_srtt + 4*m_mdev;
			m_dwTimeToCheck = max(MIN_RTO, m_dwTimeToCheck);
			//VC-fengwen on 2008/01/04 <end> : 按tcp方式计算rto

			//_AddDebugLogLine(false, _T("new CHECK_TIME = %d\n"), m_dwTimeToCheck);

			//VC-fengwen on 2008/01/04 <begin> : 快速重传及快速恢复算法
			if (m_snd.una == uSequenceNr)
			{
				if (m_cntNotFirstUna > 0)
					m_cwnd = m_ssthresh;		// 快速恢复

				m_snd.una = GetFirstUna();
				m_cntNotFirstUna = 0;
			}
			else
			{
				m_cntNotFirstUna++;
				if (m_cntNotFirstUna == DUPACKS) //快速重传
				{
					sTransferBufferEntry*	unaEntry;
					if (m_UploadBuffer.Lookup(m_snd.una, unaEntry))
					{
						SendBufferedSegment(unaEntry);
					}

					m_ssthresh = m_cwnd / 2;
					m_ssthresh = max(m_ssthresh, (int)m_UserModeTCPConfig->MaxSegmentSize);
					//跟tcp快速重传算法不同，由于每收到一个不是第一个unack的包，cwnd也会增加，所以这里cwnd不用加DUPACKS*mss。
				}
			}
			//VC-fengwen on 2008/01/04 <end> : 快速重传及快速恢复算法

		}

		delete BufferEntry;

		m_Parent->TriggerEvent(FD_WRITE);
	}

	Output();

	//if(! m_UploadBuffer.IsEmpty())
	//{
	//	//  speed up the first missed packet
	//	//POSITION pos = m_UploadBuffer.GetHeadPosition();

	//	//for(int i = 0; i < WIN_SIZE && pos; i++)
	//	//{
	//	//	BufferEntry=m_UploadBuffer.GetNextValue(pos);

	//	//	if(! BufferEntry->uSendCount && m_snd.wnd > BufferEntry->uSize)
	//	//	{
	//	//		SendBufferedSegment(BufferEntry);
	//	//		m_snd.wnd -= BufferEntry->uSize;
	//	//	}
	//	//}

	//	POSITION pos = m_UploadBuffer.GetHeadPosition();
	//	
	//	for(int i = 0; i < WIN_SIZE && pos; i++)
	//	{
	//		uint32 sn= m_UploadBuffer.GetKeyAt(pos);
	//		BufferEntry=m_UploadBuffer.GetNextValue(pos);
	//		
	//		if(::GetTickCount() - BufferEntry->uSendTime < m_dwTimeToCheck) 
	//		{
	//			continue;
	//		}
	//		else
	//		{
	//			T_TRACE("%s: resend for maybe missing segment. uSequenceNr=%d", __FUNCTION__,sn);
	//			SendBufferedSegment(BufferEntry);
	//		}
	//	}
	//}
}

void CNatSocket::CheckForTimeOut()
{
	if(m_UserModeTCPConfig == NULL)
	{
		return; // socket is not redy yet
	}

	//sTransferBufferEntry* BufferEntry;

	if(time(NULL) - m_dwSendKeepalive > TM_KEEPALIVE)
	{
		if(SendPacket(m_UserModeTCPConfig->TargetIP, m_UserModeTCPConfig->TargetPort,
			OP_NAT_PING, 0, 0)>0)
		{
			m_dwSendKeepalive = time(NULL);
		}
	}
	// -------------------------
	// Check for Segment Timeout
	// -------------------------

	//int i=0;
	//for(POSITION pos = m_UploadBuffer.GetHeadPosition(); pos && i<WIN_SIZE; i++)
	//{
	//	BufferEntry = m_UploadBuffer.GetNextValue(pos);

	//	if(::GetTickCount() - BufferEntry->uSendTime < m_dwTimeToCheck) 
	//	{
	//		continue;
	//	}
	//	else
	//	{	
	//		SendBufferedSegment(BufferEntry);
	//		T_TRACE("resend time out packet. uSequenceNr=%d\n",BufferEntry->uSequenceNr);
	//	}
	//}

	//VC-fengwen on 2008/01/04 <begin> : 如果unacknowledge的包超时则重发。
	BOOL					bFirstTimeout = TRUE;
	set<uint32>::iterator	it;
	sTransferBufferEntry*	entry = NULL;
	int						rto = Backoff(m_backoff) * m_dwTimeToCheck;

	for (it = m_unackSet.begin(); it != m_unackSet.end(); it++)
	{
		if (!m_UploadBuffer.Lookup(*it, entry))
			continue;

		if (NULL == entry)
			continue;

		if(::GetTickCount() - entry->uSendTime < (uint32)rto) 
			continue;

		if (bFirstTimeout)
		{
			bFirstTimeout = FALSE;

			m_backoff++;
			m_ssthresh = m_cwnd / 2;
			m_ssthresh = max(m_ssthresh, (int)m_UserModeTCPConfig->MaxSegmentSize);
			m_cwnd = m_ssthresh;//m_UserModeTCPConfig->MaxSegmentSize; //经实验此处设为m_ssthresh比设为mss效果好。
		}

		SendBufferedSegment(entry);
		//T_TRACE("resend time out packet. uSequenceNr=%d\n",entry->uSequenceNr);
	}
	//VC-fengwen on 2008/01/04 <end> : 如果unacknowledge的包超时则重发。

	if (m_bReNotifyWindowSize)
	{
		SendAckPacket(m_uLastAcknowledgeSequenceNr);
		m_bReNotifyWindowSize = false;
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Download implementation //
/////////////////////////////

/**
* ProcessDataPacket is colled by the udp socket (main thread) when an NAT DATA packet was recived.
* The function puts the new data into the download buffer and notifyes the CEMSocket that there are data to recive
* In case we get a empty data packet and we have a Recieving window != 0 we send an ACK with the number 0 and the new window size
*
* @param packet: pointer to the recived packet buffer.
*
* @param size: recived packet buffer size.
*/
bool CNatSocket::ProcessDataPacket(const BYTE* packet, UINT size)
{
	m_dwRecvKeepalive = time(NULL);
	ASSERT(m_UserModeTCPConfig);

	if(m_ShutDown & 0x01)
	{
		_AddDebugLogLine(false, _T("->%s: the sock is closed\n"),__FUNCTION__);
		return false; // shocket is shuting down
	}

	uint32 uSequenceNr = PeekUInt32(packet);

	if(uSequenceNr)
	{
		//-------------------
		// Buffer new Segment
		//-------------------

		sTransferBufferEntry* BufferEntry;
		// Check is this Sequence Number valid, it may be a duplicated packet
		if(uSequenceNr <= m_uLastAcknowledgeSequenceNr || m_DownloadBuffer.Lookup(uSequenceNr,BufferEntry))
		{
			// that's the down side of the new implementation, we must send an ACK for every segment
			SendAckPacket(uSequenceNr); // this may happen when our last ACK got lost, so resend it
			T_TRACE("%s: duplicate packet. uSequenceNr=%d Size=%d", __FUNCTION__, uSequenceNr, size);
			return false; // it's a duplicate just drop it
		}

		if(m_DownloadBuffer.GetCount() > 64 && uSequenceNr > m_uLastAcknowledgeSequenceNr + 25)
		{ 
			// if it is the next required segment we always have space for it
			//m_DownLocker.Unlock();
			T_TRACE("*********** recv buffer is full, drop it. used size=%d, max size=%d, uSequenceNr=%d",
				m_uDownloadBufferSize + (size-4),
				m_UserModeTCPConfig->MaxDownloadBufferSize + m_UserModeTCPConfig->MaxSegmentSize,
				uSequenceNr);

			T_TRACE("DownloadBuffer Count %d, m_uLastAcknowledgeSequenceNr %d", m_DownloadBuffer.GetCount(), m_uLastAcknowledgeSequenceNr);

			return true; // Damn it! our buffer it full, we must dropp it :'(
			//  but I must notify OnReceive, so I return true here
		}

		// add the new packet to our download buffer
		m_DownloadBuffer.SetAt(uSequenceNr, new sTransferBufferEntry(size-4, packet+4, uSequenceNr));
		m_uDownloadBufferSize += (size-4);
	}
	// its a ping to get a new window size
	else if(3*MAX_BUF_SIZE <= m_uDownloadBufferSize) // answre only when the window size is not longer 0
	{
		//_AddDebugLogLine(false, _T("->%s: ping for get new window size\n"),__FUNCTION__);
		return false; // windows ist still full just return
	}

	// Note: in cotryry to the reqular TCP we cinfirm every segment immidetly, this give's the sender a better overview over the situation
	SendAckPacket(uSequenceNr); // send a acknowledge packet

	// we have new data in buffer
	//T_TRACE("%s: uSequenceNr=%d, new recv buffer len=%d", __FUNCTION__,uSequenceNr,m_uDownloadBufferSize);

	POSITION pos = m_DownloadBuffer.GetHeadPosition();

	if(pos)
	{
		sTransferBufferEntry* BufferEntry = m_DownloadBuffer.GetValueAt(pos);

		// ups! we miss a segment
		if(BufferEntry->uSequenceNr != (m_uLastAcknowledgeSequenceNr+1)) 
		{
			return false;
		}
	}

	return true;
}

/**
* Receive is calles from CEMSocket like for a usual TCP socket,
*   The function copyes the data segments from the socket intern download buffer into the, provided buffer.
*   The segments are reasembeld according to the sequence number if a number is missing function stops
*
* Synchronisation note: This function locks the Download Buffer Mutex.
*
* @param lpBuf: pointer on the data buffer to read.
*
* @param nBufLen: buffer length.
*
* @param nFlags: unused yet.
*/
int CNatSocket::Receive(void* lpBuf, int nBufLen, int /*nFlags*/)
{ 
	// NOTE: *** This function is invoked from a *different* thread!

	ASSERT(m_UserModeTCPConfig);

	if(m_UserModeTCPConfig == NULL
	 || m_uDownloadBufferSize == 0)
	{
		SetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	uint32 toRecive = min((unsigned)nBufLen, m_uDownloadBufferSize);

	uint32 Recived = 0;
	for(POSITION pos = m_DownloadBuffer.GetHeadPosition(); pos && toRecive > Recived; pos = m_DownloadBuffer.GetHeadPosition()) // the buffer is ordered by swquence numbers
	{
		sTransferBufferEntry* BufferEntry = m_DownloadBuffer.GetValueAt(pos);

		// ups! we miss a segment
		if(BufferEntry->uSequenceNr != (m_uLastAcknowledgeSequenceNr+1)) 
		{
			T_TRACE("%s: miss a segment, uSequenceNr=%d\n", __FUNCTION__, m_uLastAcknowledgeSequenceNr+1);
			break; // and break loop
		}

		if(BufferEntry->uSequenceNr!=m_uLastRecvSequenceNr+1)
			break;
		//--------------------------------------
		// We may read the segment only partialy
		//--------------------------------------

		uint32 Size = min((toRecive - Recived),(BufferEntry->uSize - m_uCurrentSegmentPosition));
		memcpy((BYTE*)lpBuf+Recived, BufferEntry->pBuffer + m_uCurrentSegmentPosition, Size);
		Recived += Size;

		m_uCurrentSegmentPosition += Size;

		// If we ware able to read the netier segment
		if(m_uCurrentSegmentPosition == BufferEntry->uSize)
		{
			//NATTrace((uint32)this,NLE_READ,__FUNCTION__, "Read segment; Size: %u, uSequenceNr: %u", BufferEntry->uSize, BufferEntry->uSequenceNr);

			m_uLastAcknowledgeSequenceNr++; // increment our counter

			m_uCurrentSegmentPosition = 0; // reset position

			// free our download buffer
			m_uDownloadBufferSize -= BufferEntry->uSize;
			m_DownloadBuffer.RemoveAt(pos); 
			delete BufferEntry;

			m_uLastRecvSequenceNr++;
		}
	}

	//T_TRACE("%s, received: %d, left recv buffer len=%d", __FUNCTION__, Recived, m_uDownloadBufferSize);
	//NATTrace((uint32)this,NLE_RESULT,__FUNCTION__, "Recived: %u; left segments %u", Recived, m_DownloadBuffer.GetCount());

	return Recived; // return the number if bytes we gave
}

void CNatSocket::SendAckPacket(uint32 uSequenceNr)
{
	// NOTE: This function is called from a *different* thread! 
	DWORD pack[3];
	pack[0] = m_dwConnAskNumber;
	pack[1] = uSequenceNr;

	if(3 * MAX_BUF_SIZE > m_uDownloadBufferSize)
	{
		pack[2] = 3 * MAX_BUF_SIZE- m_uDownloadBufferSize;
	}
	else 
	{
		pack[2] = 0;
	}

	if (pack[2] < MAXFRAGSIZE)
	{
		m_bReNotifyWindowSize = true;
	}

//	T_TRACE("%s: uSequenceNr: %d",__FUNCTION__,  uSequenceNr);

	SendPacket(m_UserModeTCPConfig->TargetIP, m_UserModeTCPConfig->TargetPort,OP_NAT_ACK, (const uchar*)pack, 12);
}

void CNatSocket::RenewNatSock()
{
	DumpData();

	CClientReqSocket * pClientSock = DYNAMIC_DOWNCAST(CClientReqSocket, m_Parent);
	if(pClientSock)
	{
		CUpDownClient * client = pClientSock->client;
		pClientSock->client = NULL;
		if (NULL != client)
			client->socket = NULL;

		if(CNatThread::m_pHelper)
		{
			//CNatThread::m_pHelper->Disconnect(pClientSock);
			UINotify(WM_NAT_DISCONNECTED, 0, (LPARAM)pClientSock);
		}
	
		if(client)
		{
			//client->Disconnected(_T(""),true);
			UINotify(WM_NAT_DISCONNECTED, 1, (LPARAM)client);
		}
		//MODIFIED by VC-fengwen on 2007/09/28 <begin> : 解决Deadlock问题
			//theApp.uploadBandwidthThrottler->RemoveFromAllQueues(pClientSock);
		PostMessage(((CWnd*)(theApp.emuledlg))->GetSafeHwnd(), UM_REMOVEFROMALLQ_IN_THROTTLER, 0, (LPARAM)pClientSock);
		//MODIFIED by VC-fengwen on 2007/09/28 <end> : 解决Deadlock问题
	}

	if(theApp.natthread)
	{
	theApp.natthread->m_SockMap.RemoveKey(m_Parent);
	m_Parent = theApp.listensocket->OnAcceptEx(0);
	theApp.natthread->AddNatSocket(m_Parent, this);
}
}

void CNatSocket::DumpData()
{
	m_uLastSentSequenceNr = 0;
	m_uLastRecvSequenceNr = 0;
	m_uUploadBufferSize = 0;

	// DownStream
	m_uLastAcknowledgeSequenceNr = 0;
	m_uCurrentSegmentPosition = 0;
	m_uDownloadBufferSize = 0;

	m_dwSendKeepalive = m_dwRecvKeepalive =time(NULL)-TM_KEEPALIVE;

	m_uMaxSendSequenceNr = 0;

	for(POSITION pos = m_UploadBuffer.GetTailPosition();pos;)
		delete m_UploadBuffer.GetPrev(pos)->m_value;
	m_UploadBuffer.RemoveAll();

	for(POSITION pos = m_DownloadBuffer.GetTailPosition();pos;)
		delete m_DownloadBuffer.GetPrev(pos)->m_value;
	m_DownloadBuffer.RemoveAll();
}

int CNatSocket::SendPacket(uchar opcode, const uchar * data, int len)
{
	return SendPacket(m_UserModeTCPConfig->TargetIP, m_UserModeTCPConfig->TargetPort, opcode, data, len);
}

//int CNat1Handler::SendPacket(DWORD ip, WORD port, uchar opcode, const uchar * data, int len)
//{
//	Packet pack(opcode, len, OP_VC_NAT_HEADER,false);
//	if(len>0 && data) memcpy(pack.pBuffer, data, len);
//
//	SOCKADDR_IN addr;
//	addr.sin_addr.s_addr=ip;
//	addr.sin_family=AF_INET;
//	addr.sin_port = port;
//	char * pData=pack.GetPacket();
//	int nDataLen= pack.GetRealPacketSize();
//	memset(pData+1, 0, 4);
//	return sendto(theApp.clientudp->m_hSocket,pData, nDataLen, 0, (SOCKADDR*)&addr, sizeof(addr));
//}
//
//int CNat2Handler::SendPacket(DWORD ip, WORD port, uchar opcode, const uchar * data, int len)
//{
//	if(len<0 || (len && !data)) return -1;
//	if(! theApp.clientudp) return -1;
//
//	uchar* pack=new uchar[len+2];
//	pack[0] = OP_VC_NAT_HEADER+1;
//	pack[1] = opcode;
//	if(len>0 && data) memcpy(pack+2, data, len);
//
//	SOCKADDR_IN addr;
//	addr.sin_addr.s_addr=ip;
//	addr.sin_family=AF_INET;
//	addr.sin_port = port;
//	return sendto(theApp.clientudp->m_hSocket, (const char*)pack, len+2, 0, (SOCKADDR*)&addr, sizeof(addr));
//}

void CNatSocket::Output()
{
	// Compute data already in flight
	int iSent = m_uPendingWindowSize;
	
	// Compute usable send window as minimum of offered
	// and congestion windows, minus data already in flight.
	int iUsable = min(m_snd.wnd, m_cwnd);
	if(iUsable > iSent)
		iUsable -= iSent;	/* Most common case */
	else
		iUsable = 0;		/* Window closed or shrunken */

	// Compute size of segment we *could* send.
	int iSegSize = min(iUsable, (int)m_uUploadBufferSize - iSent);

	// 根据iSegSize发送一定量数据。
	sTransferBufferEntry* entry = NULL;

	while (iSegSize > 0)
	{
		if (!m_UploadBuffer.Lookup(m_snd.ptr, entry))
			break;
		
		if (NULL == entry)
			break;

		if (entry->uSize > (uint32)iSegSize && iSent > 0)//由于m_UploadBuffer是按包分的，无法精确到字节。遇到有余数，则如果网络上有包则不发。
			break;

		SendBufferedSegment(entry);
		m_snd.ptr++;
		iSegSize -= entry->uSize;
	}
}

int	CNatSocket::GetFirstUna()
{
	uint32 iRet;
	iRet = m_snd.ptr;

	set<uint32>::iterator	it;
	for (it = m_unackSet.begin(); it != m_unackSet.end(); it++)
	{
		if (*it < iRet)
			iRet = *it;
	}
	return iRet;
}


