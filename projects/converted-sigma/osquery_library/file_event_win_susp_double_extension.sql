-- Title: Suspicious Double Extension Files
-- ID: b4926b47-a9d7-434c-b3a0-adc3fa0bd13e
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2022-06-19
-- Tags: attack.stealth, attack.t1036.007
-- Description: Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((((TargetFilename="*.rar.exe" OR TargetFilename="*.zip.exe")) OR ((TargetFilename="*.exe" OR TargetFilename="*.iso" OR TargetFilename="*.rar" OR TargetFilename="*.svg" OR TargetFilename="*.zip") AND (TargetFilename LIKE '%.doc.%' OR TargetFilename LIKE '%.docx.%' OR TargetFilename LIKE '%.gif.%' OR TargetFilename LIKE '%.jpeg.%' OR TargetFilename LIKE '%.jpg.%' OR TargetFilename LIKE '%.mp3.%' OR TargetFilename LIKE '%.mp4.%' OR TargetFilename LIKE '%.pdf.%' OR TargetFilename LIKE '%.png.%' OR TargetFilename LIKE '%.ppt.%' OR TargetFilename LIKE '%.pptx.%' OR TargetFilename LIKE '%.rtf.%' OR TargetFilename LIKE '%.svg.%' OR TargetFilename LIKE '%.txt.%' OR TargetFilename LIKE '%.xls.%' OR TargetFilename LIKE '%.xlsx.%'))) AND NOT ((TargetFilename="/usr/share/icons/*")))
