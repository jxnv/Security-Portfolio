-- Title: Suspicious Parent Double Extension File Execution
-- ID: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-06
-- Tags: attack.stealth, attack.t1036.007
-- Description: Detect execution of suspicious double extension files in ParentCommandLine
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentImage="*.doc.lnk" OR ParentImage="*.docx.lnk" OR ParentImage="*.xls.lnk" OR ParentImage="*.xlsx.lnk" OR ParentImage="*.ppt.lnk" OR ParentImage="*.pptx.lnk" OR ParentImage="*.rtf.lnk" OR ParentImage="*.pdf.lnk" OR ParentImage="*.txt.lnk" OR ParentImage="*.doc.js" OR ParentImage="*.docx.js" OR ParentImage="*.xls.js" OR ParentImage="*.xlsx.js" OR ParentImage="*.ppt.js" OR ParentImage="*.pptx.js" OR ParentImage="*.rtf.js" OR ParentImage="*.pdf.js" OR ParentImage="*.txt.js")) OR ((ParentCommandLine LIKE '%.doc.lnk%' OR ParentCommandLine LIKE '%.docx.lnk%' OR ParentCommandLine LIKE '%.xls.lnk%' OR ParentCommandLine LIKE '%.xlsx.lnk%' OR ParentCommandLine LIKE '%.ppt.lnk%' OR ParentCommandLine LIKE '%.pptx.lnk%' OR ParentCommandLine LIKE '%.rtf.lnk%' OR ParentCommandLine LIKE '%.pdf.lnk%' OR ParentCommandLine LIKE '%.txt.lnk%' OR ParentCommandLine LIKE '%.doc.js%' OR ParentCommandLine LIKE '%.docx.js%' OR ParentCommandLine LIKE '%.xls.js%' OR ParentCommandLine LIKE '%.xlsx.js%' OR ParentCommandLine LIKE '%.ppt.js%' OR ParentCommandLine LIKE '%.pptx.js%' OR ParentCommandLine LIKE '%.rtf.js%' OR ParentCommandLine LIKE '%.pdf.js%' OR ParentCommandLine LIKE '%.txt.js%')))
