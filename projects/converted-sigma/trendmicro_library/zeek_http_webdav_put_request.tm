// Title: WebDav Put Request
// ID: 705072a5-bb6f-4ced-95b6-ecfa6602090b
// Status: test
// Level: low
// Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
// Date: 2020-05-02
// Tags: attack.exfiltration, attack.t1048.003
// Description: A General detection for WebDav user-agent being used to PUT files on a WebDav network share. This could be an indicator of exfiltration.
// Converted by: Sigma Universal SIEM/EDR CLI

((user_agent: "*WebDAV*" AND method: "PUT") AND NOT (((cidrmatch("10.0.0.0/8", id.resp_h) OR cidrmatch("127.0.0.0/8", id.resp_h) OR cidrmatch("172.16.0.0/12", id.resp_h) OR cidrmatch("192.168.0.0/16", id.resp_h) OR cidrmatch("169.254.0.0/16", id.resp_h)))))
