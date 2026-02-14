/*
 * $Id: TraverseStrategy.cpp 5163 2008-03-27 10:11:16Z huby $
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
#include ".\traversestrategy.h"
#include "TraverseBySvr.h"
#include "TraverseByBuddy.h"
#include "TraverseBySourceExchange.h"


CTraverseStrategy::CTraverseStrategy(const uchar * pUserhash, CTraverseStrategy * pNext)
{
	m_pNext = pNext;
	memcpy(m_UserHash, pUserhash, 16);

	m_bFinish = m_bFailed = false;
}

CTraverseStrategy::~CTraverseStrategy(void)
{
	if(m_pNext) delete m_pNext;
}

CTraverseStrategy * CTraverseBySvrFac::CreateStrategy(const uchar * pUserhash)
{
	//CTraverseStrategy * bybuddy = new CTraverseByBuddy(pUserhash, NULL);
	CTraverseStrategy * bysvr= new CTraverseBySvr(pUserhash, NULL);
	return bysvr;
}

CTraverseStrategy * CTraverseBySEFac::CreateStrategy(const uchar * pUserhash)
{
/*
	CTraverseStrategy * bysvr= new CTraverseBySvr(pUserhash, NULL);
	CTraverseBySourceExchange * bySourceExchange = new CTraverseBySourceExchange(pUserhash, bysvr);
	return bySourceExchange;
*/
	//[VC-Huby-080326] SourceExchage traverse is slow,so use CTraverseBySvr first(we will fix the CTraverseBySourceExchange slow bug in the future)
	CTraverseBySourceExchange * bySourceExchange = new CTraverseBySourceExchange(pUserhash, NULL);
	CTraverseStrategy * bysvr = new CTraverseBySvr(pUserhash, bySourceExchange);
	return bysvr;
}


