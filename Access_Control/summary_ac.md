##### PortSwigger BurpSuite Certification Summary
# Access Control
In it's simplest case, no AC is in place, meaning the attacker needs to know only the location of interesting places. These can sometimes be disclosed in some form, such as JS code.

If AC is done based on parameters, the attacker might be able to control them and give themselves escalated privileges:
  * Request parameters in direct use
  * Extendable request parameters in order to change hidden ones

In case the URL is blocked from access by frontend-control, an alternative URL in the header might circumvent the blockage:
```
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```
Sometimes the restriction is based on the HTTP method. Alternative methods might still work however, e.g. replacing `POST /admin/delete ... username=carlos` with `GET /admin/delete?username=carlos`
