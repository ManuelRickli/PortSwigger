##### PortSwigger BurpSuite Certification Summary
# Information Disclosure
Sensible information can be revealed to an attacker via multiple ways:
  * the `robots.txt` file
  * backup files
  * error messages
  * exposing it unnecessarily
  * source code (hardcoded data)
  * application behaviour

This vulnerability is commonly introduced by human errors, such as failing to remove content that will be public or faulty configuration. However, information disclosure can also arise due to flawed logic in the application and may be hard to notice in this case.

#### Methodology
It is generally a good idea to try to cause an error with a resulting error message. This can often be achieved with unexpected inputs (fuzzing).

The source code is also a valuable starting point, as it can reveal interesting data directly or hint towards a further possible step in the attack. An example is the mention of a debugging process in the code comments.

Discovering the existing directories of the server may lead to information that is not meant for the public. This can be as easy as checking webcrawling files such as the `robots.txt`, but is also possible with dedicated scanners that check for common directories. In case a version control system is within a discovered directory, more information can be exfiltrated by going through the changes.

Noteworthy is the existence of alternative request methods, such as the `TRACE` method in place of `GET`. The response might differ in a way that reveals further information on the logic of the application.
