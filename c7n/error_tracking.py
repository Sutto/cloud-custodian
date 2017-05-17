import os
import sys
from functools import partial
import logging

backend = None
environment = os.getenv('APP_ENV') or 'production'
log = logging.getLogger('custodian.error_tracking')

class Backend(object):

  def report_exception(self, *args, **kwargs):
    log.error("report_exception() called from empty backend.")
    pass

  def report(self, *args, **kwargs):
    print(args, kwargs)
    # pass

class RollbarBackend(object):

  def report_exception(self, *args, **kwargs):
    rollbar.report_exc_info(sys.exc_info(), *args, **kwargs)

  def report(self, *args, **kwargs):
    rollbar.report_message(*args, **kwargs)

log.info("Initializing error logging for %s" % environment)
if os.getenv('ROLLBAR_APP_TOKEN'):
  log.info("Using Rollbar for error logging.")
  import rollbar
  rollbar.init(os.getenv('ROLLBAR_APP_TOKEN'), environment, allow_logging_basic_config=False)
  backend = RollbarBackend()
else:
  log.error("Falling back to default error logging backend.")
  backend = Backend()

def report_exception(*args, **kwargs):
  backend.report_exception(*args, **kwargs)

def report(*args, **kwargs):
  backend.report(*args, **kwargs)
