// Title: Suspicious Double Extension File Execution
// ID: 1cdd9a09-06c9-4769-99ff-626e2b3991b8
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems), @blu3_team (idea), Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-06-26
// Tags: attack.initial-access, attack.t1566.001
// Description: Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*      .exe" OR Image="*______.exe" OR Image="*.doc.exe" OR Image="*.doc.js" OR Image="*.docx.exe" OR Image="*.docx.js" OR Image="*.gif.exe" OR Image="*.jpeg.exe" OR Image="*.jpg.exe" OR Image="*.mkv.exe" OR Image="*.mov.exe" OR Image="*.mp3.exe" OR Image="*.mp4.exe" OR Image="*.pdf.exe" OR Image="*.pdf.js" OR Image="*.png.exe" OR Image="*.ppt.exe" OR Image="*.ppt.js" OR Image="*.pptx.exe" OR Image="*.pptx.js" OR Image="*.rtf.exe" OR Image="*.rtf.js" OR Image="*.svg.exe" OR Image="*.txt.exe" OR Image="*.txt.js" OR Image="*.xls.exe" OR Image="*.xls.js" OR Image="*.xlsx.exe" OR Image="*.xlsx.js" OR Image="*⠀⠀⠀⠀⠀⠀.exe") AND (CommandLine: "*      .exe*" OR CommandLine: "*______.exe*" OR CommandLine: "*.doc.exe*" OR CommandLine: "*.doc.js*" OR CommandLine: "*.docx.exe*" OR CommandLine: "*.docx.js*" OR CommandLine: "*.gif.exe*" OR CommandLine: "*.jpeg.exe*" OR CommandLine: "*.jpg.exe*" OR CommandLine: "*.mkv.exe*" OR CommandLine: "*.mov.exe*" OR CommandLine: "*.mp3.exe*" OR CommandLine: "*.mp4.exe*" OR CommandLine: "*.pdf.exe*" OR CommandLine: "*.pdf.js*" OR CommandLine: "*.png.exe*" OR CommandLine: "*.ppt.exe*" OR CommandLine: "*.ppt.js*" OR CommandLine: "*.pptx.exe*" OR CommandLine: "*.pptx.js*" OR CommandLine: "*.rtf.exe*" OR CommandLine: "*.rtf.js*" OR CommandLine: "*.svg.exe*" OR CommandLine: "*.txt.exe*" OR CommandLine: "*.txt.js*" OR CommandLine: "*.xls.exe*" OR CommandLine: "*.xls.js*" OR CommandLine: "*.xlsx.exe*" OR CommandLine: "*.xlsx.js*" OR CommandLine: "*⠀⠀⠀⠀⠀⠀.exe*"))
