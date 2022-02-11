##### PortSwigger BurpSuite Certification Summary
# Vulnerabilities in Password-based Login
### Enumeration
Find different responses depending if the username exists. Can be a response code, slight difference in error message or response time. 

Bruteforce protection can be in place by checking for the source IP and limiting the number of requests. This can be mitigated by spoofing the source:
```
X-Forwarded-For: 1234
```
