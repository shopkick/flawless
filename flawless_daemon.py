# NOTE: As of the time of writing, python-daemon<=1.5.5 is incompatible with recent versions of lockfile. If you
# wish to use this daemon and are using python-daemon<=1.5.5 please use lockfile==0.8

# Disable relative imports, and remove magical current directory sys.path entry
from __future__ import absolute_import
import sys
if __name__ == "__main__":
    sys.path.pop(0)

import daemon
import daemon.pidlockfile
import lockfile
import os.path
import os

import flawless.server.server


def process_is_running(pid):
    try:
        # NOOP if exists, otherwise throws exception
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def get_context(pid_file_path, error_log):
    context = daemon.DaemonContext()
    context.detach_process = True
    context.working_directory = '.'
    context.stdout = error_log
    context.stderr = error_log
    if pid_file_path:
        context.pidfile = daemon.pidlockfile.TimeoutPIDLockFile(pid_file_path, acquire_timeout=2)
    return context


def main(argv):
    # Process argv
    if len(argv) <= 1:
        print "\nUsage: python flawless_daemon.py FLAWLESS_CONFIG_PATH PID_FILE_PATH RUN_DIR"
        print "    FLAWLESS_CONFIG_PATH - The path to the flawless.cfg config you want to use"
        print "    PID_FILE_PATH - The path you want to for the PID lock file"
        print "    RUN_DIR - Directory to output run data"
        return
    flawless_cfg_path = os.path.abspath(argv[1])
    pid_file_path = os.path.abspath(argv[2])
    run_dir_path = os.path.abspath(argv[3])

    # Setup logging of output
    pid = os.getpid()
    filename = os.path.join(run_dir_path, "flawless-%d.ERROR" % pid)
    error_log = open(filename, "w+", 1)

    retry = 2
    while retry > 0:
        context = get_context(pid_file_path, error_log)
        try:
            with context:
                os.setpgid(0, os.getpid())
                flawless.server.server.serve(flawless_cfg_path)
        except lockfile.LockError:
            sys.stderr.write("Error: pid file exists %s.\n" % pid_file_path)
            current_pid = context.pidfile.read_pid()
            if process_is_running(current_pid):
                sys.stderr.write("Error: Process already running %s.\n" % pid_file_path)
                sys.exit(1)
            else:
                sys.stderr.write("Error: No process running %s. Breaking lock\n" % pid_file_path)
                context.pidfile.break_lock()
                retry -= 1
        except (KeyboardInterrupt, SystemExit):
            context.pidfile.release()
            sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
