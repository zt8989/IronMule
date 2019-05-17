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
#include "./Neo/NeoConfig.h"
#include "./Neo/Address.h"

class CUpDownClient;
typedef CTypedPtrList<CPtrList, CUpDownClient*> CUpDownClientPtrList;

class CUploadQueue
{

public:
	CUploadQueue();
	~CUploadQueue();

	void	Process();
	void	AddClientToQueue(CUpDownClient* client,bool bIgnoreTimelimit = false);
	bool	RemoveFromUploadQueue(CUpDownClient* client, LPCTSTR pszReason = NULL, bool updatewindow = true, bool earlyabort = false);
	bool	RemoveFromWaitingQueue(CUpDownClient* client,bool updatewindow = true);
	bool	IsOnUploadQueue(CUpDownClient* client)	const {return (waitinglist.Find(client) != 0);}
	bool	IsDownloading(CUpDownClient* client)	const {return (uploadinglist.Find(client) != 0);}

    void    UpdateDatarates();
	uint32	GetDatarate();
    uint32  GetToNetworkDatarate();

	bool	CheckForTimeOver(CUpDownClient* client);
	int		GetWaitingUserCount() const				{return waitinglist.GetCount();}
	int		GetUploadQueueLength() const			{return uploadinglist.GetCount();}
	uint32	GetActiveUploadsCount()	const			{return m_MaxActiveClientsShortTime;}
	uint32	GetWaitingUserForFileCount(const CSimpleArray<CObject*>& raFiles, bool bOnlyIfChanged);
	uint32	GetDatarateForFile(const CSimpleArray<CObject*>& raFiles) const;
	
	POSITION GetFirstFromUploadList()				{return uploadinglist.GetHeadPosition();}
	CUpDownClient* GetNextFromUploadList(POSITION &curpos)	{return uploadinglist.GetNext(curpos);}
	CUpDownClient* GetQueueClientAt(POSITION &curpos)	{return uploadinglist.GetAt(curpos);}

	POSITION GetFirstFromWaitingList()				{return waitinglist.GetHeadPosition();}
	CUpDownClient* GetNextFromWaitingList(POSITION &curpos)	{return waitinglist.GetNext(curpos);}
	CUpDownClient* GetWaitClientAt(POSITION &curpos)	{return waitinglist.GetAt(curpos);}

#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	CUpDownClient*	GetWaitingClientByIP_UDP(const CAddress& IP, uint16 nUDPPort, bool bIgnorePortOnUniqueIP, bool* pbMultipleIPs = NULL);
	CUpDownClient*	GetWaitingClientByIP(const CAddress& IP);
#else // NEO: IP6 END
	CUpDownClient*	GetWaitingClientByIP_UDP(uint32 dwIP, uint16 nUDPPort, bool bIgnorePortOnUniqueIP, bool* pbMultipleIPs = NULL);
	CUpDownClient*	GetWaitingClientByIP(uint32 dwIP);
#endif
	CUpDownClient*	GetNextClient(const CUpDownClient* update);

	
	void	DeleteAll();
	UINT	GetWaitingPosition(CUpDownClient* client);
	
	uint32	GetSuccessfullUpCount()					{return successfullupcount;}
	uint32	GetFailedUpCount()						{return failedupcount;}
	uint32	GetAverageUpTime();

    CUpDownClient* FindBestClientInQueue();
    void ReSortUploadSlots(bool force = false);

	CUpDownClientPtrList waitinglist;
	CUpDownClientPtrList uploadinglist;

protected:
	void		RemoveFromWaitingQueue(POSITION pos, bool updatewindow);
	bool		AcceptNewClient(bool addOnNextConnect = false);
	bool		AcceptNewClient(uint32 curUploadSlots);
	bool		ForceNewClient(bool allowEmptyWaitingQueue = false);
	bool		AddUpNextClient(LPCTSTR pszReason, CUpDownClient* directadd = 0);
	void		UseHighSpeedUploadTimer(bool bEnable);
	
	static VOID CALLBACK UploadTimer(HWND hWnd, UINT nMsg, UINT nId, DWORD dwTime);
	static VOID CALLBACK HSUploadTimer(HWND hWnd, UINT nMsg, UINT nId, DWORD dwTime);

private:
	void	UpdateMaxClientScore();
	uint32	GetMaxClientScore()						{return m_imaxscore;}
    void    UpdateActiveClientsInfo(DWORD curTick);

    void InsertInUploadingList(CUpDownClient* newclient);
    float GetAverageCombinedFilePrioAndCredit();


	// By BadWolf - Accurate Speed Measurement
	typedef struct TransferredData {
		uint32	datalen;
		DWORD	timestamp;
	};
	CList<uint64> avarage_dr_list;
    CList<uint64> avarage_friend_dr_list;
	CList<DWORD,DWORD> avarage_tick_list;
	CList<int,int> activeClients_list;
    CList<DWORD,DWORD> activeClients_tick_list;
	uint32	datarate;   //datarate sent to network (including friends)
    uint32  friendDatarate; // datarate of sent to friends (included in above total)
	// By BadWolf - Accurate Speed Measurement

	UINT_PTR h_timer;
	UINT_PTR m_hHighSpeedUploadTimer;
	uint32	successfullupcount;
	uint32	failedupcount;
	uint32	totaluploadtime;
	uint32	m_nLastStartUpload;
	uint32	m_dwRemovedClientByScore;

	uint32	m_imaxscore;

    DWORD   m_dwLastCalculatedAverageCombinedFilePrioAndCredit;
    float   m_fAverageCombinedFilePrioAndCredit;
    uint32  m_iHighestNumberOfFullyActivatedSlotsSinceLastCall;
    uint32  m_MaxActiveClients;
    uint32  m_MaxActiveClientsShortTime;

    DWORD   m_lastCalculatedDataRateTick;
    uint64  m_avarage_dr_sum;

    DWORD   m_dwLastResortedUploadSlots;
	bool	m_bStatisticsWaitingListDirty;
};
