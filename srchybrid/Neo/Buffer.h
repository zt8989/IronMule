//this file is part of NeoMule
//Copyright (C)2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
//
#pragma once

class CBuffer
{
public:
	CBuffer()													{Init();}
	virtual ~CBuffer();

	virtual void	AllocBuffer(size_t uSize);

	virtual const byte*	GetBuffer() const						{return m_pBuffer;}

	virtual size_t	GetSize() const								{return m_uSize;}
	virtual bool	SetSize(size_t uSize, bool bExpend = false, size_t uPreAlloc = 0);

	virtual bool	IsValid() const								{return m_pBuffer != NULL;}
	virtual size_t	GetLength() const							{return m_uLength;}

	virtual bool	AppendData(const void* pData, size_t uLength);
	virtual bool	ShiftData(size_t uOffset);

protected:
	void			Init();
	bool			PrepareWrite(size_t uOffset, size_t uLength);

	byte*			m_pBuffer;
	size_t			m_uSize; // size of data
	size_t			m_uLength; // Length of the allocated memory
};