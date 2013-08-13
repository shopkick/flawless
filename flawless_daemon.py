# Disable relative imports, and remove magical current directory sys.path entry
from __future__ import absolute_import
import sys
if __name__ == "__main__": sys.path.pop(0)

import daemon
import daemon.pidlockfile
import lockfile
import os.path
import os

import flawless.server.server

def main(argv):
  # Process argv
  if len(argv) <= 1:
    print "\nUsage: python flawless_daemon.py FLAWLESS_CONFIG_PATH [PID_FILE_PATH]"
    print "  FLAWLESS_CONFIG_PATH - The path to the flawless.cfg config you want to use"
    print "  PID_FILE_PATH - (optional) The path you want to for the PID lock file\n"
    return
  flawless_cfg_path = os.path.abspath(argv[1])
  pid_file_path = os.path.abspath(argv[2]) if len(argv) == 3 else None

  # Initialize context
  context = daemon.DaemonContext()
  context.detach_process = True
  context.working_directory = '.'

  # Setup logging of output
  pid = os.getpid()
  filename = "flawless-%d.ERROR" % pid
  error_log = open(filename, "w+", 1)
  context.stdout = error_log
  context.stderr = error_log

  # Setup PID file
  if pid_file_path:
    context.pidfile = daemon.pidlockfile.TimeoutPIDLockFile(pid_file_path, acquire_timeout=2)

  try:
    with context:
      os.setpgid(0, os.getpid())
      flawless.server.server.serve(flawless_cfg_path)
  except lockfile.LockTimeout:
    sys.stderr.write("Error: Couldn't acquire lock on %s. Exiting.\n" % pid_file_path)
    sys.exit(1)


if __name__ == '__main__':
  main(sys.argv)
