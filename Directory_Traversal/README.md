##### PortSwigger BurpSuite Certification Summary
# Directory Traversal
The principle is to access files in the system from another directory. DT can be done when there is a source loaded from the host (e.g. an image). If the fetching of the source is not securely implemented, other sources can be accessed by altering the form.
### DT Circumventing Techniques
There are different things to try to circumvent DT protection:
  * Use absolute paths instead of relative ones
  * Expand the path so it results in a valid one after stripping (`....//....//....//etc/passwd` becomes `../../../etc/passwd`)
  * Start from the original directory (`/var/www/images/../../../etc/passwd`)
  * Append a null byte to conform to file endings (`../../../etc/passwd%00.png`)
  * Obfuscate characters (`../exploit.php` can be written as `..%2fexploit.php`)

A general approach is using the Intruder with the fuzzing DT payload. It enumerates all common methods and may result in acquiring information about possible circumvention methods.
