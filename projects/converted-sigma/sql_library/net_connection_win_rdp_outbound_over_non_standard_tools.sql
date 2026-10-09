-- Title: Outbound RDP Connections Over Non-Standard Tools
-- ID: ed74fe75-7594-4b4b-ae38-e38e3fd2eb23
-- Status: test
-- Level: high
-- Author: Markus Neis
-- Date: 2019-05-15
-- Tags: attack.lateral-movement, attack.t1021.001, car.2013-07-002
-- Description: Detects Non-Standard tools initiating a connection over port 3389 indicating possible lateral movement.
-- An initial baseline is required before using this utility to exclude third party RDP tooling that you might use.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((DestinationPort = 3389 AND Initiated = 'true') AND NOT (((Image = 'C:\\Windows\\System32\\mstsc.exe' OR Image = 'C:\\Windows\\SysWOW64\\mstsc.exe'))) AND NOT ((((Image ILIKE '%\\Avast Software\\Avast\\AvastSvc.exe' OR Image ILIKE '%\\Avast\\AvastSvc.exe')) OR (Image = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe') OR (Image = 'C:\\Windows\\System32\\dns.exe' AND SourcePort = 53 AND Protocol = 'udp') OR (Image = '') OR (Image = 'C:\\Program Files\\Mozilla Firefox\\firefox.exe') OR (Image IS NULL) OR (Image ILIKE '%\\Ranger\\SentinelRanger.exe') OR (Image ILIKE 'C:\\Program Files\\SplunkUniversalForwarder\\bin\\%') OR (Image ILIKE '%\\RDCMan.exe') OR ((Image ILIKE '%\\FSAssessment.exe' OR Image ILIKE '%\\FSDiscovery.exe' OR Image ILIKE '%\\MobaRTE.exe' OR Image ILIKE '%\\mRemote.exe' OR Image ILIKE '%\\mRemoteNG.exe' OR Image ILIKE '%\\Passwordstate.exe' OR Image ILIKE '%\\RemoteDesktopManager.exe' OR Image ILIKE '%\\RemoteDesktopManager64.exe' OR Image ILIKE '%\\RemoteDesktopManagerFree.exe' OR Image ILIKE '%\\RSSensor.exe' OR Image ILIKE '%\\RTS2App.exe' OR Image ILIKE '%\\RTSApp.exe' OR Image ILIKE '%\\spiceworks-finder.exe' OR Image ILIKE '%\\Terminals.exe' OR Image ILIKE '%\\ws_TunnelService.exe')) OR ((Image ILIKE '%\\thor.exe' OR Image ILIKE '%\\thor64.exe')) OR ((Image = 'C:\\Program Files\\TSplus\\Java\\bin\\HTML5service.exe' OR Image = 'C:\\Program Files (x86)\\TSplus\\Java\\bin\\HTML5service.exe')) OR (Image = '<unknown process>'))))
