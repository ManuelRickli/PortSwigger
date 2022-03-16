##### PortSwigger BurpSuite Certification Summary
# Server-Side Request Forgery
A way to circumvent access control is to make the server make a request from within, usually the localhost. Such requests are usually considered safe, as they originate from the server itself. Thus, something like this can be done:
```
POST /product/stock HTTP/1.1

.
.
.

stockApi=http://localhost/admin/delete?username=carlos
```
where we invoke an admin functionality directly from the site that checks the amount of stock of a product (the original stockApi was `http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=11`)

Not only the server itself is accessible through this technique, but also other backend services. Sending requests to an instance in the local network often happens without restrictive security policies, as the own machines are considered trusted.

SSRF defenses, such as input filters, can as usually be circumvented by obfuscation or alternative representations:
  * `127.0.0.1` can be written as `2130706433`, `017700000001` or `127.1`
  * An owned domain can resolve to localhost (e.g. `spoofed.burpcollaborator.net`)
  * URL encoding and case variation ot bypass blocking string

Redirects can also be utilized and are especially useful, as the request URL contains the original site and passes the filters:
```
http://shop.com/product/nextProduct?currentProductId=6&path=http://localhost:8080/admin
```
Notice that the original website, `shop.com` is included to pass the filters.

#### Blind SSRF
In case no direct result of the SSRF is seen on the front-end, an out-of-band attack can still reveal the vulnerability. In most cases, outgoing DNS traffic is permitted, allowing the attacker to make such a request to themselves.