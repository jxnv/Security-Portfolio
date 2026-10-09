// Title: BITS Transfer Job Download From Direct IP
// ID: 90f138c1-f578-4ac3-8c49-eecfd847c8b7
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-11
// Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197
// Description: Detects a BITS transfer job downloading file(s) from a direct IP address.
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID: "16403" AND (RemoteName: "*http://1*" OR RemoteName: "*http://2*" OR RemoteName: "*http://3*" OR RemoteName: "*http://4*" OR RemoteName: "*http://5*" OR RemoteName: "*http://6*" OR RemoteName: "*http://7*" OR RemoteName: "*http://8*" OR RemoteName: "*http://9*" OR RemoteName: "*https://1*" OR RemoteName: "*https://2*" OR RemoteName: "*https://3*" OR RemoteName: "*https://4*" OR RemoteName: "*https://5*" OR RemoteName: "*https://6*" OR RemoteName: "*https://7*" OR RemoteName: "*https://8*" OR RemoteName: "*https://9*")) AND NOT ((((RemoteName: "*://10.*" OR RemoteName: "*://192.168.*" OR RemoteName: "*://172.16.*" OR RemoteName: "*://172.17.*" OR RemoteName: "*://172.18.*" OR RemoteName: "*://172.19.*" OR RemoteName: "*://172.20.*" OR RemoteName: "*://172.21.*" OR RemoteName: "*://172.22.*" OR RemoteName: "*://172.23.*" OR RemoteName: "*://172.24.*" OR RemoteName: "*://172.25.*" OR RemoteName: "*://172.26.*" OR RemoteName: "*://172.27.*" OR RemoteName: "*://172.28.*" OR RemoteName: "*://172.29.*" OR RemoteName: "*://172.30.*" OR RemoteName: "*://172.31.*" OR RemoteName: "*://127.*" OR RemoteName: "*://169.254.*")) OR ((RemoteName: "*https://7-*" OR RemoteName: "*http://7-*")))))
