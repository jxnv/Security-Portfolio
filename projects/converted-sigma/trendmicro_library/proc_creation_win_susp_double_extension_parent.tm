// Title: Suspicious Parent Double Extension File Execution
// ID: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-06
// Tags: attack.stealth, attack.t1036.007
// Description: Detect execution of suspicious double extension files in ParentCommandLine
// Converted by: Sigma Universal SIEM/EDR CLI

(((ParentImage="*.doc.lnk" OR ParentImage="*.docx.lnk" OR ParentImage="*.xls.lnk" OR ParentImage="*.xlsx.lnk" OR ParentImage="*.ppt.lnk" OR ParentImage="*.pptx.lnk" OR ParentImage="*.rtf.lnk" OR ParentImage="*.pdf.lnk" OR ParentImage="*.txt.lnk" OR ParentImage="*.doc.js" OR ParentImage="*.docx.js" OR ParentImage="*.xls.js" OR ParentImage="*.xlsx.js" OR ParentImage="*.ppt.js" OR ParentImage="*.pptx.js" OR ParentImage="*.rtf.js" OR ParentImage="*.pdf.js" OR ParentImage="*.txt.js")) OR ((ParentCommandLine: "*.doc.lnk*" OR ParentCommandLine: "*.docx.lnk*" OR ParentCommandLine: "*.xls.lnk*" OR ParentCommandLine: "*.xlsx.lnk*" OR ParentCommandLine: "*.ppt.lnk*" OR ParentCommandLine: "*.pptx.lnk*" OR ParentCommandLine: "*.rtf.lnk*" OR ParentCommandLine: "*.pdf.lnk*" OR ParentCommandLine: "*.txt.lnk*" OR ParentCommandLine: "*.doc.js*" OR ParentCommandLine: "*.docx.js*" OR ParentCommandLine: "*.xls.js*" OR ParentCommandLine: "*.xlsx.js*" OR ParentCommandLine: "*.ppt.js*" OR ParentCommandLine: "*.pptx.js*" OR ParentCommandLine: "*.rtf.js*" OR ParentCommandLine: "*.pdf.js*" OR ParentCommandLine: "*.txt.js*")))
