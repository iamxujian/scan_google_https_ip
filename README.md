scan_google_https_ip
====================

scan ips which google https server(*.google.com, *.google.us, etc.) use.

### FEATURE
* send https request to test whether a ip is signed by google
* the collection of ip comes from [justjavac/Google-IPs][1]
* by modifying the code, can specify ip directly or read from local files

### REQUIREMENT
* python 2.7
* gevent
* requests
* sqlite3
* sqlalchemy

### USAGE
``./scan_google_https_ip.py``

### IN THE FUTURE
* progress indicator
* more source of ip
* more in-source document
* comfortable api, easy to custom parameter
* commandline option parser

[1]: https://github.com/justjavac/Google-IPs
