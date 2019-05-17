//this file is part of NeoMule
//Copyright (C)2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
//

#include "stdafx.h"
#include "Buffer.h"

CBuffer::~CBuffer()
{
	if(m_pBuffer)
		free(m_pBuffer);
}

void CBuffer::Init() 
{
	m_pBuffer = NULL;
	m_uSize = 0;
	m_uLength = 0;	
}

void CBuffer::AllocBuffer(size_t uLength)
{
	if(m_pBuffer)
		free(m_pBuffer);

	m_uLength = uLength;
	m_pBuffer = (byte*)malloc(uLength);
	m_uSize = 0;
}

bool CBuffer::SetSize(size_t uSize, bool bExpend, size_t uPreAlloc)
{
	if(m_uLength < uSize)
	{
		if(!bExpend)
			return false;

		m_uLength = uSize + uPreAlloc;
		m_pBuffer = (byte*)realloc(m_pBuffer,m_uLength);
	}
	m_uSize = uSize;
	return true;
}

bool CBuffer::PrepareWrite(size_t uOffset, size_t uLength)
{
	// check if there is enough space allocated for the data, and fail if no realocation cna be done
	if(uOffset + uLength > m_uLength)
	{
		size_t uPreAlloc = max(min(uLength*10,m_uSize/2), 16);
		return SetSize(uOffset + uLength, true, uPreAlloc);
	}

	// check if we are overwriting data or adding data, if the later than increase teh size accordingly
	if(uOffset + uLength > m_uSize)
		m_uSize = uOffset + uLength;
	return true;
}

bool CBuffer::AppendData(const void* pData, size_t uLength)
{
	size_t uOffset = m_uSize; // append to the very end
	if(!PrepareWrite(uOffset, uLength))
	{
		ASSERT(0); // appen must usually always success
		return false;
	}

	ASSERT(pData);
	ASSERT(m_pBuffer + uOffset + uLength < (byte*)pData || m_pBuffer + uOffset > (byte*)pData + uLength);
	memcpy(m_pBuffer + uOffset, pData, uLength);
	return true;
}

bool CBuffer::ShiftData(size_t uOffset)
{
	if(uOffset > m_uSize)
	{
		ASSERT(0); // shift must usually always success
		return false;
	}

	m_uSize -= uOffset;

	memmove(m_pBuffer, m_pBuffer + uOffset, m_uSize);
	return true;
}
