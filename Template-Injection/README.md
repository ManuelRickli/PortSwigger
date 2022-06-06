##### PortSwigger BurpSuite Certification Summary
# Server-Side Template Injection
If applicable, this is a very serious vulnerability which often leads to RCE. Consider this PHP Code using the Twig library for templating:
```
$output = $twig->render("Dear " . $_GET['name']);
```
The name parameter is evaluated directly in the statement, enabling an attack over a URL like this:
```
https://VICTIM-HOST?name={{malicious_code}}
```
### Steps
Since such vulnerabilities often go unnoticed, it is reasonable to have an idea of how to look for them. Once found, server-side template injection can often be done with ease.
#### Detect
The first approach is usually using a fuzzing string with the aim to raise an exception. This then indicates, that templates are used and the user's input is processed.
```
${{<%[%'"}}%\
```
Regardless of the outcome of the fuzzing approach, it is detrimental to identify the context in which the template is being used. The following two methods can even provide results when the fuzzing was unsuccessful or inconclusive.
##### Plaintext Context
In this case, the template is used within HTML. This can look something like this:
```
render('Hello' + username)
```
which can be checked for possible template injection with
```
https://VICTIM-HOST?username=${7*7}
```
resulting in the username being `49`.

##### Code Context
This is when the input is used within the template expression:
```
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)
```
The goal here is to break out of the statement:
```
https://VICTIM-HOST?greeting=data.username}}<tag>
```
If the statement is vulnerable (and the syntax for the used template is correct), the output will be
```
Hello Wiener<tag>
```

#### Identify
If invalid syntax does not result in an error message which reveals the used templating product, the following manual steps are useful to determine it:

![[Pasted image 20220414093538.png]]

The payload` {{7*'7'}}` returns `49` in Twig and `7777777` in Jinja2.

Using the intruder with fuzzing strings can also be an easy method of testing for template injection. 
In case ruby ERB is used, the follwing string will work:
```
<%=7*7%>
```

#### Exploit
The first step here is usually to read up on the documentation of the template engine.