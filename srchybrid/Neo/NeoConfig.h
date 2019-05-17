//this file is part of NeoMule
//Copyright (C)2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
//
//	Any code located in files under /Neo/*.* 
//	It is available to be used in projects under the therms of 
//	the GPL, as well as the BSD licence. Any changes done to this 
//	code must remain under booth this licences.
//

#pragma once

// NEO: NSX - [NeoSoruceExchange]
#define USE_NEO_SX
// NEO: NSX END

// NEO: NAT - [NatTraversal]
#define USE_NAT_T
#if defined(USE_NAT_T) && !defined(USE_NEO_SX)
#error NAT-T Requirers NeoXS
#endif
// NEO: NAT END

// NEO: IP6 - [IPv6]
#define USE_IP_6
#if defined(USE_IP_6) && !defined(USE_NEO_SX)
#error IPv6 Requirers NeoXS
#endif
// NEO: IP6 END

// NEO: MID - [ModID]
#define MOD_VERSION "Neo Mule Protocol Reference v0.1a"
// NEO: MID END

union UMuleMiscN
{
	UINT	Bits;
	struct SMiscN
	{
		UINT
		ExtendedSourceEx	: 1, // Extended Source Exchange with variable source info
		SupportsNatTraversal: 1, // NAT-T Simple Traversal UDP through NATs 
		SupportsIPv6		: 1, // IPv6 Support
		ExtendedComments	: 1, //	OP_FILEDESC <HASH 16><uint8 - rating><string - commend, max len > 1 kb>
		Reserved			: 28;
	}		Fields;
};

enum EMuleHelloTags
{
	CT_EMULE_ADDRESS		= 0xB0, // NEO SX
	CT_EMULE_SERVERIP		= 0xBA, // NEO SX
	CT_EMULE_SERVERTCP		= 0xBB, // NEO SX
	CT_EMULE_CONOPTS		= 0xBE, // NEO SX
	CT_EMULE_BUDDYID		= 0xBF, // NEO SX and addition to Hello

	// Note: as of now non of the 0xA? tags is banned by any major MOD so we can use safely them 
	CT_NEOMULE_RESERVED_0	= 0xA0,
	CT_NEOMULE_RESERVED_1	= 0xA1,
	CT_NEOMULE_RESERVED_2	= 0xA2,
	CT_NEOMULE_RESERVED_3	= 0xA3,
	CT_NEOMULE_RESERVED_4	= 0xA4,
	CT_NEOMULE_RESERVED_5	= 0xA5,
	CT_NEOMULE_RESERVED_6	= 0xA6,
	CT_NEOMULE_RESERVED_7	= 0xA7,
	CT_NEOMULE_RESERVED_8	= 0xA8,
	CT_NEOMULE_RESERVED_9	= 0xA9,
	CT_NEOMULE_MISCOPTIONS	= 0xAA,
	CT_NEOMULE_RESERVED_B	= 0xAB,
	CT_NEOMULE_RESERVED_C	= 0xAC,
	CT_NEOMULE_YOUR_IP 		= 0xAD,
	CT_NEOMULE_IP_V6		= 0xAE,
	CT_NEOMULE_SVR_IP_V6	= 0xAF,
};

#define	SOURCEEXCHANGEEXT_VERSION		1

#define OP_RENDEZVOUS			0xA0
#define OP_HOLEPUNCH			0xA1