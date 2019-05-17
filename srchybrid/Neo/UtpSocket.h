//this file is part of NeoMule
//Copyright (C)2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
//

#pragma once

#include "NeoConfig.h"
#include "..\AsyncSocketExLayer.h"
#include "Buffer.h"

#ifdef USE_NAT_T // NEO: NAT - [NatTraversal]

class CUtpSocket : public CAsyncSocketExLayer
{
public:
	CUtpSocket();
	virtual ~CUtpSocket();

	static void Process();

	static void ProcessUtpPacket(const byte *data, size_t len, const struct sockaddr *from, socklen_t fromlen);

	//Notification event handlers
	/*
	!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	!!! Note: we must ensure the layer wont be deleted when triggerign an event !!!
	!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	*/
	virtual void OnReceive(int nErrorCode)		{ TriggerEvent(FD_READ, nErrorCode, TRUE); }
	virtual void OnSend(int nErrorCode)			{ TriggerEvent(FD_WRITE, nErrorCode, TRUE);	}
	virtual void OnConnect(int nErrorCode)		{ TriggerEvent(FD_CONNECT, nErrorCode, TRUE); }
/**/virtual void OnAccept(int nErrorCode)		{ ASSERT(0); /*TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);*/ } // shell never be called
	virtual void OnClose(int nErrorCode)		{ TriggerEvent(FD_CLOSE, nErrorCode, TRUE); }

	//Operations
	virtual BOOL Create(UINT nSocketPort = 0, int nSocketType = SOCK_STREAM,
						long lEvent = FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE,
						LPCSTR lpszSocketAddress = NULL );

/**/virtual BOOL Connect(LPCSTR /*lpszHostAddress*/, UINT /*nHostPort*/)				{ASSERT(0); return FALSE;}	// shell never be called
	virtual BOOL Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen);

/**/virtual BOOL Listen(int /*nConnectionBacklog*/)										{ASSERT(0); return FALSE;}	// shell never be called
/**/virtual BOOL Accept(CAsyncSocketEx& /*rConnectedSocket*/, SOCKADDR* /*lpSockAddr*/ = NULL, int* /*lpSockAddrLen*/ = NULL) 	{ASSERT(0); return FALSE;}	// shell never be called

	virtual void Close();

	virtual BOOL GetPeerName(SOCKADDR* lpSockAddr, int* lpSockAddrLen);
#ifdef _AFX
/**/virtual BOOL GetPeerName(CString& /*rPeerAddress*/, UINT& /*rPeerPort*/)			{ASSERT(0); return FALSE;}	// not implemented
#endif
	
	virtual int Receive(void* lpBuf, int nBufLen, int nFlags = 0);
	virtual int Send(const void* lpBuf, int nBufLen, int nFlags = 0);

	virtual BOOL ShutDown(int nHow = sends);

	virtual bool IsUtpLayer() {return true;}

	//Attributes
	BOOL GetSockOpt(int nOptionName, void* lpOptionValue, int* lpOptionLen);
	BOOL SetSockOpt(int nOptionName, const void* lpOptionValue, int nOptionLen);

protected:
	friend void utp_state(void* userdata, int state);
	friend void utp_error(void* userdata, int errcode);
	friend void utp_read(void* userdata, const byte* bytes, size_t count);
	friend size_t utp_get_rb_size(void* userdata);
	friend void utp_write(void* userdata, byte* bytes, size_t count);
	friend void got_incoming_connection(void *userdata, struct UTPSocket *socket);

	void				Setup(struct UTPSocket* Socket);

	struct UTPSocket*	m_Socket;
	uint8				m_ShutDown;

	CBuffer				m_ReadBuffer;
	CBuffer				m_WriteBuffer;
};

#endif // NEO: NAT END