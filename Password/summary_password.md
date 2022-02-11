##### PortSwigger BurpSuite Certification Summary
# Vulnerabilities in Password-based Login
### Enumeration
Find different responses depending if the username exists. Can be a response code, slight difference in error message or response time. 

Bruteforce protection can be in place by checking for the source IP and limiting the number of requests. This can be mitigated by spoofing the source:
```
X-Forwarded-For: 1234
```
If the implemented brute-force protection resets after a successful login, the attack can be launched by providing valid credentials after every brute-force try. It is recommendable to set a time in between the requests to avoid the protection to be triggered nonetheless.

#### Multiple Attempts per Request
Sometimes it is possible to try multiple attempts with a single request, an important tool when user rate limiting is in place.
Example JSON:
```
POST /login HTTP/1.1
...
{
  "username":"admin",
  "password": [
    "1234",
    ...
    "zzzz"
  ]
}
```
If any of the provided passwords match, it can be that the response is the logged in page. In this case,the password is still unknown. However, the response can be opened in a browser (assuming the request was made with the burp suite repeater), yielding the account page of the victim.

### Two-Factor Authentication
2FA can be bypassed in case the logic on which it is built upon is flawed. An example is a successful login state after entering correct credentials but before the 2FA took place. In this case, the 2FA step can be skipped entirely.

It can also be that the website uses cookies in order to know whose account is being processed at the moment. A valid request from the attackers login process (after logging in, before the 2FA is generated) can be used to change the current user to the victim's username. This then generates a 2FA for the victim, which can be easily brute-forced.

#### Stay logged-in
A persistent cookie is sometimes used to remember a user session for a long time. If this cookie is composed of predictable elements, the attacker can try to generate a cookie that is valid for a victim, e.g.:
```
Cookie: stay-logged-in: base64(username:MD5(password))
```
This allows the attacker to bruteforce passwords for a known user until a valid cookie is generated which lets the attacker bypass the login alltogether.
