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
#include "MapKey.h"
#pragma warning(disable:4516) // access-declarations are deprecated; member using-declarations provide a better alternative
#pragma warning(disable:4244) // conversion from 'type1' to 'type2', possible loss of data
#pragma warning(disable:4100) // unreferenced formal parameter
#pragma warning(disable:4702) // unreachable code
#include <crypto51/rsa.h>
#pragma warning(default:4702) // unreachable code
#pragma warning(default:4100) // unreferenced formal parameter
#pragma warning(default:4244) // conversion from 'type1' to 'type2', possible loss of data
#pragma warning(default:4516) // access-declarations are deprecated; member using-declarations provide a better alternative
#include "./Neo/NeoConfig.h"
#include "./Neo/Address.h"

#define	 MAXPUBKEYSIZE		80

#define CRYPT_CIP_REMOTECLIENT	10
#define CRYPT_CIP_LOCALCLIENT	20
#define CRYPT_CIP_NONECLIENT	30

#pragma pack(1)
struct CreditStruct_29a{
	uchar		abyKey[16];
	uint32		nUploadedLo;	// uploaded TO him
	uint32		nDownloadedLo;	// downloaded from him
	uint32		nLastSeen;
	uint32		nUploadedHi;	// upload high 32
	uint32		nDownloadedHi;	// download high 32
	uint16		nReserved3;
};
struct CreditStruct{
	uchar		abyKey[16];
	uint32		nUploadedLo;	// uploaded TO him
	uint32		nDownloadedLo;	// downloaded from him
	uint32		nLastSeen;
	uint32		nUploadedHi;	// upload high 32
	uint32		nDownloadedHi;	// download high 32
	uint16		nReserved3;
	uint8		nKeySize;
	uchar		abySecureIdent[MAXPUBKEYSIZE];
};
#pragma pack()

enum EIdentState{
	IS_NOTAVAILABLE,
	IS_IDNEEDED,
	IS_IDENTIFIED,
	IS_IDFAILED,
	IS_IDBADGUY,
};

class CClientCredits
{
	friend class CClientCreditsList;
public:
	CClientCredits(CreditStruct* in_credits);
	CClientCredits(const uchar* key);
	~CClientCredits();

	const uchar* GetKey() const					{return m_pCredits->abyKey;}
	uchar*	GetSecureIdent()					{return m_abyPublicKey;}
	uint8	GetSecIDKeyLen() const				{return m_nPublicKeyLen;}
	CreditStruct* GetDataStruct() const			{return m_pCredits;}
	void	ClearWaitStartTime();
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	void	AddDownloaded(uint32 bytes, const CAddress& ForIP);
	void	AddUploaded(uint32 bytes, const CAddress& ForIP);
#else // NEO: IP6 END
	void	AddDownloaded(uint32 bytes, uint32 dwForIP);
	void	AddUploaded(uint32 bytes, uint32 dwForIP);
#endif
	uint64	GetUploadedTotal() const;
	uint64	GetDownloadedTotal() const;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	float	GetScoreRatio(const CAddress& ForIP) const;
#else // NEO: IP6 END
	float	GetScoreRatio(uint32 dwForIP) const;
#endif
	void	SetLastSeen()					{m_pCredits->nLastSeen = time(NULL);}
	bool	SetSecureIdent(const uchar* pachIdent, uint8 nIdentLen); // Public key cannot change, use only if there is not public key yet
	uint32	m_dwCryptRndChallengeFor;
	uint32	m_dwCryptRndChallengeFrom;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	EIdentState	GetCurrentIdentState(const CAddress& ForIP) const; // can be != IdentState
	uint32	GetSecureWaitStartTime(const CAddress& ForIP);
	void	SetSecWaitStartTime(const CAddress& ForIP);
#else // NEO: IP6 END
	EIdentState	GetCurrentIdentState(uint32 dwForIP) const; // can be != IdentState
	uint32	GetSecureWaitStartTime(uint32 dwForIP);
	void	SetSecWaitStartTime(uint32 dwForIP);
#endif
protected:
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	void	Verified(const CAddress& ForIP);
#else // NEO: IP6 END
	void	Verified(uint32 dwForIP);
#endif
	EIdentState IdentState;
private:
	void			InitalizeIdent();
	CreditStruct*	m_pCredits;
	byte			m_abyPublicKey[80];			// even keys which are not verified will be stored here, and - if verified - copied into the struct
	uint8			m_nPublicKeyLen;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	CAddress		m_dwIdentIP;
#else // NEO: IP6 END
	uint32			m_dwIdentIP;
#endif
	uint32			m_dwSecureWaitTime;
	uint32			m_dwUnSecureWaitTime;
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	CAddress		m_dwWaitTimeIP;			   // client IP assigned to the waittime
#else // NEO: IP6 END
	uint32			m_dwWaitTimeIP;			   // client IP assigned to the waittime
#endif
};

class CClientCreditsList
{
public:
	CClientCreditsList();
	~CClientCreditsList();
	
			// return signature size, 0 = Failed | use sigkey param for debug only
#ifdef USE_IP_6 // NEO: IP6 - [IPv6]
	uint8	CreateSignature(CClientCredits* pTarget, uchar* pachOutput, uint8 nMaxSize, const CAddress& ChallengeIP, uint8 byChaIPKind, CryptoPP::RSASSA_PKCS1v15_SHA_Signer* sigkey = NULL);
	bool	VerifyIdent(CClientCredits* pTarget, const uchar* pachSignature, uint8 nInputSize, const CAddress& dwForIP, uint8 byChaIPKind);
#else // NEO: IP6 END
	uint8	CreateSignature(CClientCredits* pTarget, uchar* pachOutput, uint8 nMaxSize, uint32 ChallengeIP, uint8 byChaIPKind, CryptoPP::RSASSA_PKCS1v15_SHA_Signer* sigkey = NULL);
	bool	VerifyIdent(CClientCredits* pTarget, const uchar* pachSignature, uint8 nInputSize, uint32 dwForIP, uint8 byChaIPKind);
#endif

	CClientCredits* GetCredit(const uchar* key) ;
	void	Process();
	uint8	GetPubKeyLen() const			{return m_nMyPublicKeyLen;}
	byte*	GetPublicKey()					{return m_abyMyPublicKey;}
	bool	CryptoAvailable();
protected:
	void	LoadList();
	void	SaveList();
	void	InitalizeCrypting();
	bool	CreateKeyPair();
#ifdef _DEBUG
	bool	Debug_CheckCrypting();
#endif
private:
	CMap<CCKey, const CCKey&, CClientCredits*, CClientCredits*> m_mapClients;
	uint32			m_nLastSaved;
	CryptoPP::RSASSA_PKCS1v15_SHA_Signer*		m_pSignkey;
	byte			m_abyMyPublicKey[80];
	uint8			m_nMyPublicKeyLen;
};
