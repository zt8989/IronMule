#pragma once

//#include "preferences.h"
//#include "afxwin.h"
// CPPgXtreme dialog

class CPPgXtreme2 : public CPropertyPage
{
	DECLARE_DYNAMIC(CPPgXtreme2)

public:
	CPPgXtreme2();
	virtual ~CPPgXtreme2();

	// Dialog Data
	enum { IDD = IDD_PPG_Xtreme2 };

	virtual BOOL OnApply();
	virtual BOOL OnInitDialog();

	void Localize();


protected:
	void LoadSettings();

	// Generated message map functions
	afx_msg void OnSettingsChange() {SetModified();}
	DECLARE_MESSAGE_MAP()

	// for dialog data exchange and validation
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	
public:
	afx_msg void OnBnClickedAntiLeecher(); //Xman Anti-Leecher
	afx_msg void OnBnClickedDlpreload(); //Xman DLP
};
