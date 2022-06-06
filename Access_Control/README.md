##### PortSwigger BurpSuite Certification Summary
# Access Control
In it's simplest case, no AC is in place, meaning the attacker needs to know only the location of interesting places. These can sometimes be disclosed in some form, such as JS code (see information disclosure).

## Horizontal vs Vertical
Accessing resources of another user which has the same level of priviledges is called horizontal priviledge escalation. If, on the other hand, resources are accessed that should not be available to a "normal" user, we speak of vertical priviledge escalation. It is common that horizontal privesc can lead to a vertical one by compromising a user with higher priviledges and then accessing this user's functionalities.

### Vertical Privesc
If AC is done based on parameters, the attacker might be able to control them and give themselves escalated privileges:
  * Request parameters in direct use (`?admin=true`)
  * Extendable request parameters in order to change hidden ones (e.g. use an email change form to also change the `roleid` to a priviledged userd by supplying the addition parameter)

In case the URL is blocked from access by frontend-control, an alternative URL in the header might circumvent the blockage:
```
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```
Sometimes the restriction is based on the HTTP method. Alternative methods might still work however, e.g. replacing `POST /admin/delete ... username=carlos` with `GET /admin/delete?username=carlos`.

### Horizontal Privesc
Often the methodologies of horizontal privesc are identical to the ones described above. However, it might be benefitial in terms of complexity to compromise an administrative user's account (horizontal) and then accessing the functionalities (vertical), which is in contrast to accessing administrative functionalitites directly.

#### Multi-Step Processes
When using multiple steps to perform an action, such as changing a user's priviledges, all of the steps need to be checked for legit access. Is this not the case, the vulnerable step can be repeated by an unauthorized user.

#### Referrer Header
AC over a header can be abused by altering the request header. One example is the `Referer` header, which tells from which location the request was made from. Referring from an `\admin` link could therefore allow access to all it's sub-pages, even if the user doesn't have access to the admin page at all.