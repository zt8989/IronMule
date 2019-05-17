//this file is part of NeoMule
//Copyright (C)2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
//

#include "stdafx.h"
#include "UtpSocket.h"
#include "../../libutp/utp.h"
#include "../emule.h"
#include "../ClientUDPSocket.h"
#include "../ListenSocket.h"
#include <set>

#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]

std::set<CUtpSocket*> g_UtpSockets;

CUtpSocket::CUtpSocket()
{
	m_Socket = NULL;

	m_ReadBuffer.AllocBuffer(64*1024/*, false, false*/); // Note: UTP can push more data into the buffer than expected
	m_WriteBuffer.AllocBuffer(16*1024);

	m_ShutDown = 0;

	g_UtpSockets.insert(this);
}

CUtpSocket::~CUtpSocket()
{
	g_UtpSockets.erase(this);

	Setup(NULL);
}

void send_to(void *userdata, const byte *data, size_t len, const struct sockaddr *to, socklen_t tolen)
{
	CClientUDPSocket* clientudp = ((CClientUDPSocket*)userdata);
	clientudp->SendUtpPacket(data, len, to, tolen);
}

void utp_read(void* userdata, const byte* bytes, size_t count)
{
	CUtpSocket* pSocket = ((CUtpSocket*)userdata);
	if(pSocket->m_ShutDown & 0x01) // socket is shuting down
		return;
	pSocket->m_ReadBuffer.AppendData(bytes, count);
	pSocket->OnReceive(0);
}

size_t utp_get_rb_size(void* userdata)
{
	CUtpSocket* pSocket = ((CUtpSocket*)userdata);
	return pSocket->m_ReadBuffer.GetSize();
}

void utp_write(void* userdata, byte* bytes, size_t count)
{
	CUtpSocket* pSocket = ((CUtpSocket*)userdata);
	ASSERT(count <= pSocket->m_WriteBuffer.GetSize());
	memcpy(bytes, pSocket->m_WriteBuffer.GetBuffer(), count);
	pSocket->m_WriteBuffer.ShiftData(count);
	pSocket->OnSend(0);
}

void utp_state(void* userdata, int state)
{
	CUtpSocket* pSocket = ((CUtpSocket*)userdata);
	switch(state)
	{
	case UTP_STATE_CONNECT:
		pSocket->m_nLayerState = CUtpSocket::connected;
		pSocket->OnConnect(0);
	case UTP_STATE_WRITABLE:
		pSocket->OnSend(0);
		break;
	case UTP_STATE_EOF:
		pSocket->m_nLayerState = CUtpSocket::closed;
		pSocket->OnClose(0);
	case UTP_STATE_DESTROYING:
		pSocket->Setup(NULL);
		break;
	}
}

void utp_error(void* userdata, int errcode)
{
	CUtpSocket* pSocket = ((CUtpSocket*)userdata);
	pSocket->m_nLayerState = CUtpSocket::aborted;
	pSocket->Setup(NULL);
	pSocket->OnClose(errcode);
}

void utp_overhead(void *userdata, bool send, size_t count, int type)
{
	//CUtpSocket* pSocket = ((CUtpSocket*)userdata);
}

void got_incoming_connection(void *userdata, struct UTPSocket *socket)
{
	//CClientUDPSocket* clientudp = ((CClientUDPSocket*)userdata);
	CClientReqSocket* newclient = new CClientReqSocket; // this installs itself: theApp.listensocket->AddSocket(this);
	CUtpSocket* pSocket = newclient->InitUtpSupport();
	pSocket->m_nLayerState = CUtpSocket::connected;
	pSocket->Setup(socket);
	newclient->AsyncSelect(FD_WRITE | FD_READ | FD_CLOSE);
}

void CUtpSocket::Process()
{
	for(std::set<CUtpSocket*>::iterator I = g_UtpSockets.begin(); I != g_UtpSockets.end(); I++)
	{
		CUtpSocket* This = (*I);
		if(This->m_ShutDown & 0x02) // socket is shuting down
			continue;

		if(This->m_Socket && This->m_WriteBuffer.GetSize() != 0)
			UTP_Write(This->m_Socket, This->m_WriteBuffer.GetSize());
	}
}

void CUtpSocket::ProcessUtpPacket(const byte *data, size_t len, const struct sockaddr *from, socklen_t fromlen)
{
	UTP_IsIncomingUTP(&got_incoming_connection, &send_to, theApp.clientudp, data, len, from, fromlen);
}

BOOL CUtpSocket::Create(UINT /*nSocketPort*/, int /*nSocketType*/, long lEvent, LPCSTR /*lpszSocketAddress*/)
{
	m_pOwnerSocket->AsyncSelect(lEvent);
	return TRUE;
}

BOOL CUtpSocket::Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	if(m_nLayerState == unconnected)
	{
		struct UTPSocket *socket = UTP_Create(&send_to, theApp.clientudp, lpSockAddr, nSockAddrLen);

		m_nLayerState = connecting;
		Setup(socket);
		UTP_Connect(socket);

		return TRUE;
	}
	return FALSE;
}

void CUtpSocket::Setup(struct UTPSocket* Socket)
{
	if(Socket)
	{
		ASSERT(m_Socket == NULL);
		m_Socket = Socket;

		UTP_SetSockopt(m_Socket, SO_SNDBUF, (int)m_WriteBuffer.GetLength());
		UTP_SetSockopt(m_Socket, SO_RCVBUF, (int)m_ReadBuffer.GetLength());

		UTPFunctionTable utp_callbacks = {&utp_read, &utp_write, &utp_get_rb_size, &utp_state, &utp_error, &utp_overhead};
		UTP_SetCallbacks(m_Socket, &utp_callbacks, this);
	}
	else
	{
		ASSERT(m_Socket);
		UTP_Close(m_Socket);
		UTP_SetCallbacks(m_Socket, NULL, NULL); // make sure this will not be refered anymore
		m_Socket = NULL;
	}
}

void CUtpSocket::Close()
{
	if(m_nLayerState == connected)
	{
		m_nLayerState = closed;
		Setup(NULL);
		OnClose(0);
	}
}

int CUtpSocket::Receive(void* lpBuf, int nBufLen, int /*nFlags*/)
{
	if(m_nLayerState != connected)
	{
		WSASetLastError(WSAENOTCONN);
		return SOCKET_ERROR;
	}

	if(m_ReadBuffer.GetSize() == 0) // buffer is empty
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	size_t ToGo = min(m_ReadBuffer.GetSize(), (size_t)nBufLen);
	memcpy(lpBuf, m_ReadBuffer.GetBuffer(), ToGo);
	m_ReadBuffer.ShiftData(ToGo);
	return ToGo;
}

int CUtpSocket::Send(const void* lpBuf, int nBufLen, int /*nFlags*/)
{
	if(m_nLayerState != connected)
	{
		WSASetLastError(WSAENOTCONN);
		return SOCKET_ERROR;
	}

	if(m_WriteBuffer.GetSize() == m_WriteBuffer.GetLength()) // buffer is full
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	size_t ToGo = min(m_WriteBuffer.GetLength() - m_WriteBuffer.GetSize(), (size_t)nBufLen);
	m_WriteBuffer.AppendData(lpBuf, ToGo);
	return ToGo;
}

BOOL CUtpSocket::ShutDown(int nHow)
{
	m_ShutDown |= (uint8)(nHow+1);
		// receives = 0 -> 1 = 10
		// sends = 1    -> 2 = 01
		// both = 2	    -> 3 = 11
	return TRUE;
}

BOOL CUtpSocket::GetPeerName(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
{
	if(!m_Socket)
		return FALSE;
	UTP_GetPeerName(m_Socket, lpSockAddr, lpSockAddrLen);
	return TRUE;
}

BOOL CUtpSocket::GetSockOpt(int nOptionName, void* lpOptionValue, int* lpOptionLen)
{
	if(!m_Socket)
		return FALSE;
	switch(nOptionName)
	{
	case TCP_NODELAY:
		if(lpOptionLen)
			*((char*)lpOptionValue) = 0; // This function is yet not implemented, and besides we don't need it anyway
		return TRUE;
	case SO_RCVBUF:
		if(*lpOptionLen != sizeof(int))
			return FALSE;
		*((int*)lpOptionValue) = m_ReadBuffer.GetLength();
		return TRUE;
	case SO_SNDBUF:
		if(*lpOptionLen != sizeof(int))
			return FALSE;
		*((int*)lpOptionValue) = m_WriteBuffer.GetLength();
		return TRUE;
	default:
		return FALSE;
	}
}

BOOL CUtpSocket::SetSockOpt(int nOptionName, const void* lpOptionValue, int nOptionLen)
{
	if(!m_Socket)
		return FALSE;
	switch(nOptionName)
	{
	case TCP_NODELAY:
		// I havn't implement the nagle Alghorytm becouse we don't need it, we usualy send's larger packets.
		// If you think we need this funtion anyway, fill free to implement it, it isn't so complicated.
		return FALSE;
	case SO_RCVBUF:
	{
		if(nOptionLen != sizeof(int))
			return FALSE;
		int PreAlloc = *((int*)lpOptionValue);
		if(m_ReadBuffer.GetSize() < PreAlloc)
			PreAlloc = 0; // we can not set less than we have in buffer
		else
			PreAlloc -= m_ReadBuffer.GetSize();
		// SetSize(used size to be set must not change, expantion is allowed, additional length to allocate)
		m_ReadBuffer.SetSize(m_ReadBuffer.GetSize(), true, PreAlloc); 
		UTP_SetSockopt(m_Socket, SO_RCVBUF, (int)m_ReadBuffer.GetLength());
		return TRUE;
	}
	case SO_SNDBUF:
	{
		if(nOptionLen != sizeof(int))
			return FALSE;
		int PreAlloc = *((int*)lpOptionValue);
		if(m_WriteBuffer.GetSize() < PreAlloc)
			PreAlloc = 0; // we can not set less than we have in buffer
		else
			PreAlloc -= m_WriteBuffer.GetSize();
		// SetSize(used size to be set must not change, expantion is allowed, additional length to allocate)
		m_WriteBuffer.SetSize(m_WriteBuffer.GetSize(), true, PreAlloc);
		UTP_SetSockopt(m_Socket, SO_SNDBUF, (int)m_WriteBuffer.GetLength());
		return TRUE;
	}
	default:
		return FALSE;
	}
}

#endif // NEO: NAT END