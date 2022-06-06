##### PortSwigger BurpSuite Certification Summary
# HTTP Host Header Attack
The `Host` Header is a mandatory header from HTTP/1.1 onwards and specifies the domain for which the request is intended for. It is used to counter ambiguity when virtual hosts, load balancers or reverse proxies are deployed. So if multiple domains resolve to the same IP, the host header is used by the server to further distinguish where the traffic should be routed to.

Attacks are enabled by applications using the host header in an usnafe way, such as:
```
<a href="https://_SERVER['HOST']/support">Contact support</a>
```
This code fetches the host's URL from the header, a user controllable input.

Another risk arises when not understanding the behaviour on related infrastructure. Other headers than he `Host` header can override it, thus circumventing any security mechanisms on it. This scenario happens mainly when using third-party modules which implement their own logic and have default behaviours, which might not be known by the developers.

## Testing for Vulnerabilities in the Host Header
### Supply an arbitrary Host header
In this way, one can find out if it is possible to change the Host header and still reach the target website. This can happen when an unrecognized Host header has the target as a fallback.
Especially Content Delivery Networks (CDN) consider only the Host header, therfore other methods need to be tried.
### Check for flawed Validation
In case the Host header is validated in some way, a flaw in the implementation might be exploitable. It is important to be able to still reach the target, so the correct host has to be specified somewhere and pass the validation step.

###### Omitting the Port
```
GET /example HTTP/1.1
Host: VICTIM-HOST:bad-stuff-here
```
###### Include Victim Host in other Domain
If only matching is applied, for example when arbitrary subdomains are allowed, it is possible to reach the target when it's domain is contained in the Host header string. You can then either host your own domain with the victim's domain name included or utilize an already compromised subdomain.
```
GET /example HTTP/1.1
Host: OTHER-DOMAIN-VICTIM-HOST

GET /example HTTP/1.1
Host: hacked-subdomain.VICTIM-HOST
```
### Send ambiguous Requests
By identifying and exploiting discrepancies in how different systems retrieve the Host header, you may be able to issue an ambiguous request that appears to have a different host depending on which system is looking at it.

###### Duplicate Host Headers
When two systems regard different Host headers it makes it possible to deliver a malicious one.
```
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
```
###### Supply absolute URLs
Often the systems are designed to consider abolute URLs in the request path as well. This leaves the opportunity to inject something else in the Host header.
```
GET https://VICTIM-HOST/ HTTP/1.1
Host: bad-stuff-here
```
Different protocols might also yield different results.

###### Add Line Wrapping
Adding spaces in front of the Host header can trigger different behaviour. It can be used to circumvent the prevention of two Host headers while having the one considered by one system and the other by the second.
```
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```
### Inject Host Override Headers
When there is an intermediate step between you and the host, other headers are often used to tell the designated system which host is the target, as the Host header can take on the value of the intermediate system.
There are several header one can try. However, the `X-Forwarded-For` is the most prevalent used in this scenario:
* X-Forwarded-Host
* X-Host
*  X-Forwarded-Server
*  X-HTTP-Host-Override
*  Forwarded

## Exploitation
There are several ways how Host header attacks can be supported to work. One example is a XSS vulnerability exploitable via Host header. However, the victim's Host header is not controllable. In this case, cache poisoning is a way to deliver the malicious header to a victim.

Even when the Host header doesn't seem to be considered, it can still be the case. For example when the Host header is used to check for acces control. Is something available as an internal user, this might work:
```
GET VICTIM-HOST/admin HTTP/1.1
Host: localhost
```
This works also if there is an information disclosure containing the domain or IP of an internal system. Here enumeration can also help.

**In both cases it's worth trying to make a request to the collaborator first to see how the Host header is used.**