// Title: Arbitrary File Download Via GfxDownloadWrapper.EXE
// ID: eee00933-a761-4cd0-be70-c42fe91731e7
// Status: test
// Level: medium
// Author: Victor Sergeev, oscd.community
// Date: 2020-10-09
// Tags: attack.command-and-control, attack.t1105
// Description: Detects execution of GfxDownloadWrapper.exe with a URL as an argument to download file.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\GfxDownloadWrapper.exe" AND (CommandLine contains "http://" OR CommandLine contains "https://")) AND NOT ((CommandLine contains "https://gameplayapi.intel.com/")))
