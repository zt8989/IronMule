/*
 * $Id: NatThread.h 5115 2008-03-25 04:42:15Z huby $
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

//  AUTHOR: yunchenn, 2006/12/01
//  the thread for nat traversal

#include "NatSocket.h"
#include <afxtempl.h>
#include "updownclient.h"
#include "ListenSocket.h"
#include "TraverseStrategy.h"
#include <afxmt.h>

#define WM_NAT_DISCONNECTED		(WM_USER + 7791)
// CNatThread
#define NAT_E_NOPEER		0x00000001
#define NAT_E_TIMEOUT		0x00000002

#define NAT_S_SYNC			0x00010000
#define NAT_S_WAKEUP		0x00020000
//#define NAT_S_CONNACK		0x00020000

class CNatTravHelper
{
public:
	virtual void AddLogTextV(UINT /*uFlags*/, EDebugLogPriority /*dlpPriority*/, LPCTSTR /*pszLine*/, va_list /*argptr*/)
	{
	}
	virtual void Disconnect(CClientReqSocket * /*client*/)
	{
	}
};

class USERHASH
{
public:
	USERHASH()
	{
	}
	USERHASH(const uchar * id)
	{
		memcpy(userhash, id, 16);
	}
	uchar userhash[16];
	bool operator<(const USERHASH & id2) const
	{
		return memcmp(userhash, id2.userhash, 16) < 0;
	}
	bool operator==(const USERHASH & id2) const
	{
		return memcmp(userhash, id2.userhash, 16) == 0;
	}
	bool operator>(const USERHASH & id2) const
	{
		return memcmp(userhash, id2.userhash, 16) > 0;
	}
};

class CUnconnSocket
{
public:
	CUnconnSocket(DWORD sip, WORD sport, CAsyncSocketEx * s, const uchar *id);
	~CUnconnSocket();
	//int SendConnectReq();
	int SendPingPacket();

	DWORD		m_dwSvrIp;
	WORD		m_wSvrPort;
	int			m_nPassivePing;
	DWORD		m_SendPingTime, m_SendConnAckTime;
	DWORD		m_dwClientIp;
	WORD		m_wClientPort;
	CAsyncSocketEx * m_Sock;
	//CUpDownClient * m_Client;
	int			m_nTraverseType;
	DWORD		m_dwState;
	uchar		m_ClientId[16];
	DWORD		m_dwConnAskNumber;
};

class CNatThread : public CWinThread
{
	DECLARE_DYNCREATE(CNatThread)
	friend class CNatSocket;
	friend class CNatSocket2;

public:
	virtual ~CNatThread();
protected:
	CNatThread();           // 动态创建所使用的受保护的构造函数

	DWORD m_dwSvrRetTime, m_dwSendConnTime;
	DWORD m_dwTraverseBySvr;
	DWORD m_dwSvrIp;
	WORD m_wSvrPort;
	CList<CUnconnSocket*, CUnconnSocket*> m_UnConnectSocket;
	CList<USERHASH,USERHASH&> m_UnconnectBuffer;
	CRBMap<CAsyncSocketEx*, CNatSocket*> m_SockMap;
	CRBMap<USERHASH, CAsyncSocketEx *> m_TempASock;
	CRBMap<USERHASH, CNatSocket *> m_NatSockPool;
	CRBMap<USERHASH, CTraverseStrategy *> m_TraverseStrategy;
	CMutex m_Mutex;
	bool m_bRegister;
	DWORD m_RegisterTime, m_dwSvrKeepalive;
	//VC-fengwen on 2007/12/28 <begin> : 对服务器的注册重试改为指数退避。
	enum {INIT_ATTEMPT_INTERVAL = 4};
	DWORD m_dwRegAttemptTimes; 
	DWORD m_dwRegNextAttempInterval;
	//VC-fengwen on 2007/12/28 <end> : 对服务器的注册重试改为指数退避。

	time_t m_tmNextRefreshSvr;
	
	DWORD m_dwSendStaticsTime;
	WORD m_wTraverseBySvr, m_wTraverseBySE; // VC-SearchDream[2007-06-08]: new way statics

	void SendConnBuffer(bool bByBuddy);
	void CheckConnection();
	void SendKeepAlive();
	void RefreshServerIp();
	void RegisterMe(DWORD sip, WORD sport);
	CUnconnSocket * FindUnconnectSocket(const uchar * id);
	CUnconnSocket * FindUnconnectSocketByIP(DWORD ip, WORD port);
	CNatSocket * FindNatSocket(DWORD ip, WORD port, DWORD sk);
	//int ExistConnection(const uchar * id);
	bool ProcessStrategyPacket(USERHASH uh, DWORD ip, WORD port, const uchar * pData, int nDataSize);
	bool SwitchNextStrategy(const USERHASH & UsrHash);

	virtual BOOL InitInstance();
	virtual int ExitInstance();
	virtual BOOL Run();

	void OnReping(DWORD ip, WORD port, const uchar * pData, int nDataSize);
	//void OnReping2(DWORD ip, WORD port, const uchar * pData, int nDataSize);
	//void OnSync2(DWORD ip, WORD port, const uchar * pData, int nDataSize);
	void OnPing(DWORD ip, WORD port, const uchar * pData, int nDataSize);
	void OnSync(DWORD ip, WORD port, const uchar * pData, int nDataSize);
protected:
	DECLARE_MESSAGE_MAP()
public:
	void CheckStrategies();
	void RemoveStrategy( const uchar * pUserhash ); 

	int GetTimeout(CAsyncSocketEx * sock);
	void Connect(CAsyncSocketEx * sock, const uchar * clientid, CTraverseFactory * pFac);
	//void Connect(CAsyncSocketEx * sock, const uchar * clientid);
	int Send(CAsyncSocketEx * sock, const void * data, int len);
	int Receive(CAsyncSocketEx * sock, void * data, int len);
	bool ProcessPacket(const BYTE* packet, UINT size, uint32 ip, uint16 port);
	//bool ProcessPacket2(uchar opcode, const BYTE* packet, UINT size, uint32 ip, uint16 port);
	BOOL IsSocketConnected(CAsyncSocketEx * sk);
	void RemoveSocket(CAsyncSocketEx * sock,bool bDisconnectAll=false,const uchar* pUserHash=NULL);
	void RemoveSocketInUnconn(POSITION pos);
	void RemoveSocketInUnconn(CAsyncSocketEx * sock);
	DWORD GetUsedTime(CAsyncSocketEx * sock);
	void RemoveNatSocket(const uchar *UserId);
	void ResetNatSocket(CAsyncSocketEx * pOldKey, CAsyncSocketEx * pNewKey);
	bool GetAddr(const uchar * UserHash, DWORD & ip, WORD & port);
	CNatSocket * FindNatSocket(const uchar * pUserhash);
	bool WakeupNatSocketFromPool(const uchar * pUserhash, DWORD ip, WORD port, DWORD dwConnAck);
	CNatSocket *WakeupNatSocketFromPool(const uchar * pUserhash);
	CAsyncSocketEx * GetTempASock(const uchar * pUserhash);
	void RemoveTempASock(const uchar * id);
	bool IsServerRegistered(){return m_bRegister;}

	uint16 GetUDPPort(CAsyncSocketEx * sock); // VC-SearchDream[2007-04-13]: For Low2Low2Low

	CAsyncSocketEx* RemoveUnconnSocket(const uchar * id); //ADDED by VC-fengwen on 2007/10/15


	void SetTraversalSvr(DWORD ip, WORD port)
	{
		m_dwSvrIp = ip;
		m_wSvrPort = port;
	}
	void GetTraversalSvr(DWORD & ip, WORD & port)
	{
		ip = m_dwSvrIp;
		port = m_wSvrPort;
	}
	int GetSocketCount()
	{
		return m_SockMap.GetCount();
	}
	void AddNatSocket(CAsyncSocketEx * asock, CNatSocket * nsock);
#ifdef _DEBUG
	void Test();
#endif
	static CNatTravHelper * m_pHelper;
};

inline CString UserHashToString(const uchar * hash)
{
	CString sElement;
	CString strId;

	for (int iIndex=0; iIndex<16; iIndex+=4)
	{
		sElement.Format(_T("%02X%02X%02X%02X"), hash[iIndex], hash[iIndex+1], hash[iIndex+2], hash[iIndex+3]);
		strId.Append(sElement);
	}

	return strId;
}
extern void GetMyUserHash(uchar * id);

//#if defined(_DEBUG) || defined(_BETA) || defined(_VCALPHA)
#if defined(_DEBUG) || defined(_BETA)
	extern void _AddDebugLogLine(bool bAddToStatusBar, LPCTSTR pszLine, ...);
#else
	#define _AddDebugLogLine
#endif

#ifdef _DEBUG
	extern void _AddLogLine(bool bAddToStatusBar, LPCTSTR pszLine, ...);
#else
	#define _AddLogLine
#endif
