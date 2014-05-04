Burp Proxy reflux log parser: Burp proxy text log converter to CSV and SQLLite
===========

Reflux for Burp log parsing and conversion

Released as open source by NCC Group Plc - http://www.nccgroup.com/
 
Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

http://www.github.com/nccgroup/burp-reflux

Released under AGPL see LICENSE for more information

What I tried before
-------------
Previous there was Python 2 implementation which when I hacked to Python 3 didn't work (hasn't been touched in four years):
* http://blog.gdssecurity.com/labs/2010/8/10/constricting-the-web-the-gds-burp-api.html
* https://github.com/GDSSecurity/burpee

So in short I rewrote.

Why
-------------
Managers of pentest teams sometimes need Burp logs in Excel friendly formats for querying.

What it does
-------------
* takes a Burp Proxy ASCII log
* parsers
* takes a subset (raises issues if you want more) of the fields into a Python object
* spits out parts of said object into CSV and SQLLite

Example
-------------
```
[i] NCC Group burp proxy log reflux conversion tool - https://github.com/nccgroup
[i] No filename provided
[i] Processing C:\Users\Ollie\Desktop\BURPLogDay1
[i] Burplogs class initialized
[i] File read into memory sucessfully
[i] Opened: 0cc2465e1d189a3c07c74f5d3f283a5dc9594eedab9d6391a2d17718c0b7cf9a.csv for CSV output
[i] Opened: 0cc2465e1d189a3c07c74f5d3f283a5dc9594eedab9d6391a2d17718c0b7cf9a.db for SQLLite output
[i] Created table
[i] Actually processing
[i] Completed processing - number of entries: 9780
[i] All output written - number of entries: 9780
```

Testing
-------------
It has been tested with one 500MB log from April 2014 (so a Burp version around then) which resulted in 9.7K entries