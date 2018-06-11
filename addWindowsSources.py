#!/usr/bin/python

version='0.1'

"""
addWindowsSources.py
28 November, 2016
by Tim Underhay
Kensington Technology Associates, Limited
tim.underhay@kensingtontechlimited.com
http://kensingtontechlimited.com

MIT License

Copyright (c) 2016, Kensington Technology Associates, Limited

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

This project makes use of the grequests module written by Kenneth Reitz, which is licensed under the BSD license.
"""

import sys
import os
import getopt
import csv
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) #Suppress certificate warnings for HTTPS LC connections, as they are almost always self-signed
from urllib import quote_plus
import urllib2
import urlparse
from requests.auth import HTTPBasicAuth
import tempfile
import subprocess

global found
found=False
import imp
try: #try importing the grequests module, and set found=True if it is present. This enables async IO if module is present
  imp.find_module('grequests')
  import grequests
  found = True
except ImportError:
  pass


def usage():
  print 'Usage: ' + sys.argv[0] + """ [OPTIONS]

Adds Windows event sources to SA Log Collector from a CSV file.  The first line of the CSV will be skipped, assuming that it's a header.
The Event Category must already be defined in the Windows Collection configuration of your Log Collector.
All fields will be URL-encoded by this script
*** This script will by default run in synchronous mode, which is potentially slow when adding many event sources.  Installation of the 'grequests' python module will enable asynchronous mode, which should greatly increase execution speed for large data sets.

Example: addWindowsSources.py -f mycsv.csv -h logcollector -u admin -p netwitness -c Security

CSV Format and example:

eventsource_address,port_number,transport_mode,debug,enabled,cert_name,validate_server,render_locale,windows_type,resolve_sids,sids_interval,sids_timeout,override_channels
"dc1.mydomain.local","5985","http","0","true","","false","en-US","Domain Controller","true","14400","60","" 
"host1.mydomain.local","5985","http","0","true","","false","en-US","Non-Domain Controller","true","14400","60","" 

Options:
  -f, --file        CSV filename
  -d, --url         URL to download CSV file from.  Supercedes --file
  -h, --host        Hostname of Log Collector
  -c, --category    Windows Event Category to add event sources to
  -u, --user        Username to authenticate to Log Collector with
  -p, --password    Password to authenticate to Log Collector with
  -r, --rest        REST port to connect to (optional).  Default is 50101
  -s, --ssl         Enable SSL (optional).  Only do this if SSL is 'on' in /rest/config/ssl of your Log Collector's API tree
  -?, --help        This help message
"""
  sys.exit(2)


def parseCSV(filename):
  csvD=[]

  try:
    with open(filename,'rb') as csvFile:
        for row in csv.reader(csvFile, delimiter=',', skipinitialspace=True):
          csvD.append(row)
  except:
    print 'ERROR: unable to open file ' + filename
    sys.exit(1)

  return csvD
 
def downloadCSV(url):
  try:
    with tempfile.NamedTemporaryFile('wb',delete=False) as file:
      file.close()
      command = "curl -k -s --anyauth --fail '" + url + "' -o " + file.name
      subprocess.check_call(command, shell=True) #had to switch from check_output to check_call to preserve Python 2.6 compatibility
      csvD=parseCSV(file.name)
  except subprocess.CalledProcessError, e:
    #print "ERROR fetching URL: 'curl' exited with status " + str(e.returncode) + ", output: " + str(e.output)
    print "ERROR fetching URL: 'curl' exited with status " + str(e.returncode) #can't grab output due to check_call
    print "Command: " + command
    sys.exit(1)
  else:
    print 'Fetched file from URL ' + url
  os.unlink(file.name)
  return csvD
  
def olddownloadCSV(url): #original CSV downloader method.  Switched to using curl to enable proper authentication.
  try:
    resp = urllib2.urlopen(url)
    with tempfile.NamedTemporaryFile('wb',delete=False) as file:
      file.write(resp.read())
      file.close()
      csvD=parseCSV(file.name)
  except urllib2.URLError, e:
    print 'ERROR ' + str(e) + ' downloading from URL ' + url
    sys.exit(1)
  except urllib2.HTTPError:
    print 'HTTP Error: ' + str(e) + ' downloading from URL ' + url
    sys.exit(1)
  else:
    print 'Fetched file from URL ' + url
  os.unlink(file.name)
  return csvD

def main(argv):

  ssl=False
  global restPort
  restPort='50101' #This should work for nearly all but can still be set from CLI

  try:
    opts, args = getopt.getopt(argv, 'f:d:h:c:u:p:r:s?', ['file=','url=','host=','category=','user=','password=','rest=','ssl','help'] )
  except getopt.GetoptError:
    raise
    usage()
  for opt,arg in opts:
    if opt in ('-?','--help'):
      usage()
    elif opt in ('--file', '-f'):
      filename=arg
      proceed=1
    elif opt in ('-d','--url'):
      url=arg
      proceed=1
    elif opt in ('--category', '-c'):
      global categoryName
      categoryName=arg
    elif opt in ('-u','--user'):
      user=arg
    elif opt in ('-h','--host'):
      global host
      host=arg
    elif opt in ('-p','--password'):
      password=arg
    elif opt in ('-s','--ssl'):
      ssl=True
    elif opt in ('-r','--rest'):
      restPort=arg

  if set(['user', 'password', 'proceed']) <= set(vars().keys()) and set(['categoryName', 'host', 'restPort' ]) <= set(globals().keys()):
    pass
  else:
    usage()
    
  proto='http://'
  if ssl:
    proto='https://'

  csvDict=[]

  if 'url' in vars() or 'url' in globals():
    csvDict=downloadCSV(url)
  else:
    csvDict=parseCSV(filename)

  del csvDict[0] #remove first line of CSV, assuming it's the definition
  
  urlList=[]
  
  if not found:
    print 'Using synchronous mode.  If the CSV is large, the script could take some time to complete.  Install python module "grequests" to use asynchronous mode (but NOT if this is an SA host!!!)'


  for entry in csvDict:
    eventsource_address,port_number,transport_mode,debug,enabled,cert_name,validate_server,render_locale,windows_type,resolve_sids,sids_interval,sids_timeout,override_channels = entry

    uri='/logcollection/windows/eventsources/' + categoryName + '?msg=add&force-content-type=text/plain&expiry=600&eventsource_address=' + eventsource_address

    if port_number:
      uri += '&port_number=' + port_number

    if transport_mode:
      uri += '&transport_mode=' + quote_plus(transport_mode)


    if debug:
      uri += '&debug=' + quote_plus(debug)
    
  
    if enabled:
      uri += '&enabled=' + quote_plus(enabled)

  
    if cert_name:
      uri += '&cert_name=' + quote_plus(cert_name)
  
    if validate_server:
      uri += '&validate_server=' + quote_plus(validate_server)

  
    if render_locale:
      uri += '&render_locale=' + quote_plus(render_locale)

  
    if windows_type:
      uri += '&windows_type=' + quote_plus(windows_type)

  
    if resolve_sids:
      uri += '&resolve_sids=' + quote_plus(resolve_sids)

  
    if sids_interval:
      uri += '&sids_interval=' + quote_plus(sids_interval)

  
    if sids_timeout:
      uri += '&sids_timeout=' + quote_plus(sids_timeout)

  
    if override_channels:
      uri += '&override_channels=' + quote_plus(override_channels)

    url=proto + host + ':' + restPort + uri
    urlList.append(url)
    

    if not found:
      try:
        response = requests.get(url,auth=HTTPBasicAuth(user,password), verify=False, timeout=5)
        response.raise_for_status()
      except requests.exceptions.ConnectTimeout:
        print 'Connection to ' + host + ':' + restPort + ' timed out'
        sys.exit(1)
      except requests.ConnectionError, e:
        print 'ERROR connecting to host ' + host + ':' + restPort
        print str(e)
        sys.exit(1)
      except requests.HTTPError, e:
        if e.response.status_code == 401 :
          print 'ERROR connecting to host ' + host + ':' + restPort + ': ' + str(e)
        else:
          print 'ERROR adding source ' + eventsource_address + ':' + port_number  + ' to ' + host + ':' + restPort +  ' Event Category ' + categoryName + ': ' + str(e)
        sys.exit(1)
      except:
        raise
      else:
        if response.text.rstrip() != 'Success':
          print "WARNING adding source " + eventsource_address + ':' + port_number + ' to ' + host + ':' + restPort + ' Event Category ' + categoryName + ': ' + response.text.rstrip()
        else:
          print "Added source " + eventsource_address + ':' + port_number + ' to ' + host + ':' + restPort + ' Event Category ' + categoryName
    
  if found:
    print 'Using Asynchronous mode'
    try:
      reqs = (grequests.get(u, hooks = {'response' : responseHandler}, auth=HTTPBasicAuth(user,password), verify=False, timeout=5) for u in urlList)
      grequests.map(reqs,exception_handler=urlException)
    except:
      raise


def responseHandler(response, **kwargs):
  o = urlparse.urlparse(response.request.url)
  args = urlparse.parse_qs(o.query)
  
#  try:
#    response.raise_for_status()
#  except requests.HTTPError,e:
#    print 'ERROR adding host ' + args['eventsource_address'][0] + ':' + args['port_number'][0] + ' to ' + o.netloc +  ' category ' + categoryName + ': ' + e.response.text
  
  if response.text.rstrip() != 'Success':
    print "WARNING adding source " + args['eventsource_address'][0] + ':' + args['port_number'][0] + ' to ' + o.netloc + ' Event Category ' + categoryName + ': '  + response.text.rstrip()
  else:
    print "Added source " + args['eventsource_address'][0] + ':' + args['port_number'][0] + ' to ' + o.netloc + ' Event Category ' + categoryName + ': '  + response.text.rstrip()
    

def urlException(request, exception):
  o = urlparse.urlparse(request.url)
  args = urlparse.parse_qs(o.query)
  
  try:
    raise exception #we re-raise the exception so we can handle it
  except requests.HTTPError, e:
    if e.response.status_code == 401 :
      print 'ERROR connecting to host ' + host + ':' + restPort + ': ' + str(e)
    else:
      print 'ERROR adding source ' + eventsource_address + ':' + port_number  + ' to ' + host + ':' + restPort +  ' Event Category ' + categoryName + ': ' + str(e)
    sys.exit(1)
  except requests.ConnectTimeout:
    print 'Connection to ' + host + ':' + restPort + ' timed out'
    sys.exit(1)
  except requests.ConnectionError, e:
    print 'ERROR connecting to host ' + o.netloc
    print str(e)
    sys.exit(1)
  else:
    pass

    
if __name__ == "__main__":
  main(sys.argv[1:])
