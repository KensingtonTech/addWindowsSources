# addWindowsSources: Bulk Add Windows Sources to RSA Security Analytics

*addWindowsSources* allows one to add Windows WinRM event sources to SA Log Collectors, in bulk.  The source is a CSV file, which can be stored on the local host or it can be fetched from a URL by the script.

URL fetching makes this script ideal for scheduling a periodic import of event sources from a Windows Domain, as enterprises are continually adding new Windows hosts.  This can significantly reduce the administrative burden of managing Windows event sources in SA.

It is tested with RSA Security Analytics 10.6.x and 10.5.x.


## Prerequisites

1.  A UNIX-like system (e.g. Linux or MacOS) with either Python 2.6 or 2.7 installed.  

2.  For asynchronous (i.e. faster) operation, the 'grequests' Python module must be installed.  Please see the full documentation page at http://knowledgekta.com for more info.

3.  A *local* SA Log Collector account with at least logcollection.manage permissions.  Having only an account under **Admistration->Security->Users** in the UI is insufficient.

4.  A Windows Event Category must already be defined on the Log Collector.  One must add Windows Event Sources to an Event Category.  Please see the SA documentation at http://sadocs.emc.com.


## Installation

1.  Using your file transfer tool of choice (e.g. scp, sftp, etc), upload *addWindowsSources*.py to the system.

2.  Move the file to your preferred executable directory.  We recommend /usr/local/bin
`mv addWindowsSources.py /usr/local/bin`

3.  'chmod' the file to be executable.
`chmod +x /usr/local/bin/addWindowsSources.py`


## Usage

This tool adds Windows event sources to SA Log Collector from a CSV file.  The first line of the CSV will be skipped, assuming that it's a header.
The Event Category must already be defined in the Windows Collection configuration of your Log Collector.
All fields will be URL-encoded by this script

*** This script will by default run in synchronous mode, which is potentially slow when adding many event sources.  Installation of the 'grequests' python module will enable asynchronous mode, which should greatly increase execution speed for large data sets.

Example, using a local CSV:  `addWindowsSources.py -f sampleCSV.csv -h logcollector -u admin -p netwitness -c Security --delete`

Example, fetching the CSV from a URL:  `addWindowsSources.py -d 'https://user:password@csvhost/sampleCSV.csv' -h logcollector -u admin -p netwitness -c Security --delete`


## CSV Format and example
```
eventsource_address,port_number,transport_mode,debug,enabled,cert_name,validate_server,render_locale,windows_type,resolve_sids,sids_interval,sids_timeout,override_channels
dc1.mydomain.local,5985,http,0,true,,false,en-US,Domain Controller,true,14400,60,
dc2.mydomain.local,5985,http,0,true,,false,en-US,Domain Controller,true,14400,60,
host1.mydomain.local,5985,http,0,true,,false,en-US,Non-Domain Controller,true,14400,60,
```

## Options:
```
  -f, --file        CSV filename
  --delete          Delete event sources from Log Collector which are not present in the import CSV.  Matches by hostname
  -d, --url         URL to download CSV file from.  Supercedes --file
  -h, --host        Hostname of Log Collector
  -c, --category    Windows Event Category to add event sources to
  -u, --user        Username to authenticate to Log Collector with
  -p, --password    Password to authenticate to Log Collector with
  -r, --rest        REST port to connect to (optional).  Default is 50101
  -s, --ssl         Enable SSL (optional).  Only do this if SSL is 'on' in /rest/config/ssl of your Log Collector's API tree
  -?, --help        This help message
```