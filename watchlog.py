#!/usr/bin/env python3

"""
MIT License

Copyright (c) 2021 Cyril Delétré

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
"""

from datetime import datetime, timedelta
import requests
import json
import sys
import argparse
from pathlib import Path
from threading import Timer,Thread,Event
import signal

# the URL scheme to downlaod the daily update log (compare and check with yours)
URLSCHEME = 'https://logs.{0}.hosting.ovh.net/{1}.{0}.hosting.ovh.net/osl/{1}.{0}.hosting.ovh.net-{2}.log'
UPDATE_DELAY = 300 # default ovh update delay
CONFIG_EXAMPLE = { "cluster":"cluster123", "vhost":"abcdefgh", "user":"username", "password":"yourpassword", "refresh":"300"}

class OVHlog:
  def __init__(self, user, password, cluster, vhost, logfile_dir, refresh=UPDATE_DELAY, urlscheme=URLSCHEME):

    self._user = user                   # username of the ovh statistics and logs account
    self._password = password           # password of the ovh statistics and logs account
    self._cluster = cluster             # name of the ovh cluster (eg. cluster012)
    self._vhost = vhost                 # master name of the website vhost (eg. abcdefgh)
    self._refresh = int(refresh)        # refresh interval
    self._urlscheme = urlscheme         # logs download URL scheme
    self._etag = ''                     # last etag of the downloaded logs
    self._offset = 0                    # last offset of the downloaded logs (used to download only new data on each refresh)
    self._ddmmyyyy = ''                 # current date of the log
    self._yyyymmdd = ''                 # current date for logfile name
    self._logfile_dir = logfile_dir     # directory place to write log files (Path type)
    self._logfile = None                # logfile to write downloaded logs (File type)
    self._printlog_enable= False        # printing of log to stdout
    self._printerr_enable= True         # printing of error to stderr
    self._verbose_enable = False        # verbose printing to stderr
    self._timer_thread = None           # the timer thread used for periodic refresh

  def __del__(self):
    """
      clean exit on object deletion
    """

    if self._timer_thread is not None:
      self._timer_thread.cancel()
      self._timer_thread = None

    if self._logfile is not None:
      self._logfile.close()

  def _stdout(self, txt):
    """
      print to stdout txt and flush
    """

    sys.stdout.write(txt)
    sys.stdout.flush()

  def _stderr(self, txt):
    """
      print to stderr txt and flush
    """

    sys.stderr.write(txt)
    sys.stderr.flush()

  def _print_error(self, txt):
    """
      print text error to stderr if printing error is enabled
    """

    if self._printerr_enable:
      self._stderr(txt)

  def _print_log(self, txt):
    """
      print log text to stdout if enabled
    """

    if self._printlog_enable:
      self._stdout(txt)

  def _verbose(self, txt):
    """
      print verbose text to stderr if enabled
    """

    if self._verbose_enable:
      self._stderr(txt)

  def _write_log(self, txt):
    """
      write text log to logfile if set
    """

    if self._logfile is not None:
      self._logfile.write(txt)
      self._logfile.flush()

  def _repeat(self):
    """
      function triggered by the timer thread
        update logs
        launch a new timer thread
    """
    self.update()
    self._verbose('next update in {} seconds ({})\n'.format(self._refresh,str(datetime.now() + timedelta(seconds = self._refresh))))
    self._timer_thread = Timer(self._refresh,self._repeat)
    self._timer_thread.start()
 
  def set_logfile(self,filepath=None):
    """
      function to set the log destination file
      parameters:
        - filepath: a Path (optionnal)
    """
    if self._logfile is not None:
      self._logfile.close()

    if filepath is None:
      filepath = self._logfile_dir / '{}-{}.log'.format(self._vhost, self._yyyymmdd)

    if filepath.exists():
      self._offset = filepath.stat().st_size

    self._logfile = filepath.open('a')

  def set_printlog(self, enable=True):
    """
      function to enable/disable printing of the logs to stdout
    """
    self._printlog_enable = enable

  def set_printerr(self, enable=True):
    """
      function to enable/disable printing of the errors to stderr
    """

    self._printerr_enable = enable

  def set_verbose(self, enable=True):
    """
      function to enable/disable printing of the verbose messages to stderr
    """

    self._verbose_enable = enable

  def set_refresh(self, refresh=UPDATE_DELAY):
    """
      function to set the refresh interval
    """

    if refresh < UPDATE_DELAY:
      refresh = UPDATE_DELAY
      self._print_error('refresh interval must be >= {}'.format(UPDATE_DELAY))
    self._refresh = int(refresh)

  def get_url(self):
    """
      function to get the download url of the current day logs
    """

    return self._urlscheme.format(self._cluster,self._vhost,self._ddmmyyyy)

  def get_http_headers(self):
    """
      function to get the headers of the http request
        If-None-Match is used to detect on the server if a new version must be download
        Range is used to download only the new lines
    """
  
    headers = {}

    if self._etag != '':
      headers['If-None-Match'] = self._etag

    if self._offset > 0:
      headers['Range'] = 'bytes={}-'.format(self._offset)

    return headers
  
  def get_http_content(self):
    """
      function to run the http request
        update the offset if new data have been received
    """
    url = self.get_url()

    response = requests.get(url, auth=(self._user,self._password), headers=self.get_http_headers())

    if response.status_code in [200,206]:
      self._offset += int(response.headers['Content-length'])    

    return response

  def update_ddmmyyyy(self, delta=--UPDATE_DELAY):
    """
      function to update the current ddmmyyyy
        if day has changed it reset the offset, etag and the logfile
    """
    now_delay = datetime.now() + timedelta(seconds = delta)
    new_ddmmyyyy = now_delay.strftime("%d-%m-%Y")
    if new_ddmmyyyy != self._ddmmyyyy:
      self._offset = 0
      self._etag = ''
      self._ddmmyyyy = new_ddmmyyyy
      self._yyyymmdd = now_delay.strftime("%Y-%m-%d")
      self.set_logfile()
    
  def update(self):
    """
      update function to poll for new log data
    """

    self.update_ddmmyyyy()                      # update the ddmmyyyy

    self._verbose('fetching data...\n')
    http_response = self.get_http_content()     # fetch data

    if http_response.status_code in [200,206]:  # 200 for new initial data, 206 for new data part
      self._print_log(http_response.text)       # print logs if enabled
      self._write_log(http_response.text)       # write logs to file

    elif http_response.status_code == 404:      # no data available yet (empty or potential error in the request URL)
      self._verbose('no data available yet\n')

    elif http_response.status_code == 416:      # no new data (nothing new after the offset)
      self._verbose('no new data available yet\n')

    else:                                       # http error code not handled
      self._print_error('oops HTTP error: {}\n'.format(http_response.status_code))

  def start_update(self):
    """
      start the repeat loop
    """
    if self._timer_thread is None:
      self._repeat()

  def stop_update(self):
    """
      stop the repeat loop
    """
    if self._timer_thread is not None:
      self._timer_thread.cancel()
      self._timer_thread = None

def signal_handler(sig, frame):
    """
      just a dummy signal handler function
    """
    print('You pressed Ctrl+C!')

def main(args):

  if not args.config.exists():
    print('{} does not exist'.format(args.config))
    print('Please create the config file based on this example:')
    print(json.dumps(CONFIG_EXAMPLE, indent=2))
    exit(1)

  if not args.destination_dir.exists():
    print('{} does not exist'.format(args.destination_dir))
    exit(1)

  # configure the signal handler for CTRL+C
  signal.signal(signal.SIGINT, signal_handler)

  # load the parameter from the json config file
  with open(args.config,'r') as json_file:
    config = json.load(json_file)

  # setup the ovhlog with the provided parameters
  ovhlog = OVHlog(config['user'], config['password'], config['cluster'], config['vhost'], args.destination_dir, config['refresh'])

  if args.printlog:
    ovhlog.set_printlog(True)   # enable printing the log

  if args.verbose:
    ovhlog.set_verbose(True)    # enable verbose mode
    print('Press Ctrl+C to stop')

  if args.silent:
    ovhlog.set_printerr(False)  # disable printing error

  ovhlog.start_update()         # start the update loop

  # run until a signal is caught (eg. CTRL+C)
  signal.pause() 

  ovhlog.stop_update()          # stop the update loop

  exit(0)

if __name__ == '__main__':

  # setup of the command line argument parser
  parser = argparse.ArgumentParser()
  parser.add_argument('--config','-c',help='specify an alternate config file', type=lambda p: Path(p).absolute(), default=Path(__file__).absolute().parent / "config.json")
  parser.add_argument('--destination-dir','-d',help='destination directory for logs', type=lambda p: Path(p).absolute(), default=Path(__file__).absolute().parent / "logs")
  parser.add_argument('--verbose','-v',help='enable verbose printing to stderr',action='store_true')
  parser.add_argument('--printlog','-p',help='enable printing logs to stdout',action='store_true')
  parser.add_argument('--silent','-s',help='disable printing error to stderr',action='store_true')

  if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

  args = parser.parse_args()

  # call main with parsed arguments
  main(args)
