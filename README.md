# Cortex Analyzers and Responders

## Analyzers

### Elasticsearch

* **Windows User Logon IPs** - Pulls list of successfull (4625) and unsuccessfull (4625) logon events for a user observable and resturns IPs as observables.  Default window is 12 hours.   Max returned restuls is 100.  This "max results" is sent to Elasticsearch as "size".  This limit could probably be easily hit.
  * **todo**
    * Address "max results".  Perhaps update the query to add aggregations for unique addresses instead of a simple match query?
    * Summary
    * Artifacts
    * Templates

### Headless Chromium

These need a path to local copy of Chromium/Chrome binary.  **Do not** use snap version as there are odd permissions issues.  A blank profile (in /tmp) is created for each run.

* **DOM** - Pulls rendered DOM for URL observable.
* **Screenshot** - Pulls screenshot for URL observable.

### HTTPInfo

* **Redirects** - Returns redirect history for URL observable using HTTP HEAD request and Python Requests library.

### SentinelOne

* **DeepVisibility DNSQuery** - Pulls list of systems ("host" observable) that made DNS requests to URL, FQDN, or DNS.  URLs are parsed with Python's urlsplit.  Uses SentinelOne's API, specifically DeepVisibility.
  * **todo**
    * currently using "DNSRequest contains", this can match more than initial observable, should add more info to response with unique list of domains containing initial observable.

## Responders

### SentinelOne

* **HashBlacklister** - Adds SHA1 hash observable to site blacklist.

## Templates

* Headless_Chromium
* SentinelOne_DeepVisibility_DNSQuery

## TODO

* should be checking for proxy, cacert settings and using them if available