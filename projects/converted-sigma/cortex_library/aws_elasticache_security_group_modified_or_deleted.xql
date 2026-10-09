// Title: AWS ElastiCache Security Group Modified or Deleted
// ID: 7c797da2-9cf2-4523-ba64-33b06339f0cc
// Status: test
// Level: low
// Author: Austin Songer @austinsonger
// Date: 2021-07-24
// Tags: attack.impact, attack.t1531
// Description: Identifies when an ElastiCache security group has been modified or deleted.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (eventSource = "elasticache.amazonaws.com" and (eventName = "DeleteCacheSecurityGroup" or eventName = "AuthorizeCacheSecurityGroupIngress" or eventName = "RevokeCacheSecurityGroupIngress" or eventName = "AuthorizeCacheSecurityGroupEgress" or eventName = "RevokeCacheSecurityGroupEgress"))
