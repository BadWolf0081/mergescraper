#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import argparse
from datetime import datetime
import configparser

"""
scan_abends.py

Scan all files in a configured folder for ABEND lines like:
07:04:33 24.11.2025|BATCHMAN:* ... following job has stopped unexpectedly: JOBS[(0731 11/23/25),(JOBS)].TEST_ABEND (#J1140098).

Requires two additional files next to this script (will be created with templates if missing):
- scan_config.ini
    [scan]
    folder = /path/to/scan

- targets.cfg
    email=you@example.com
    jobs=TEST_ABEND,ANOTHER_JOB

Requires 'mail' command (usually provided by mailutils or mailx package on Linux).
"""


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# Regex to extract time, date, schedule, job from the example lines.
ABEND_RE = re.compile(
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<date>\d{2}\.\d{2}\.\d{4}).*?following job has stopped unexpectedly:\s+'
        r'(?P<sched>[^\[\].\s]+)\[.*?\]\.(?P<job>[^\s(]+)',
        re.IGNORECASE
)

def ensure_config_files(config_path, targets_path):
        """Create template config files if they don't exist."""
        if not os.path.exists(config_path):
                cfg = configparser.ConfigParser()
                cfg['scan'] = {'folder': '.'}
                with open(config_path, 'w') as f:
                        cfg.write(f)

        if not os.path.exists(targets_path):
                with open(targets_path, 'w') as f:
                        f.write("# email= recipient address for the abend report\n")
                        f.write("# jobs= comma-separated list of job names to report (case-insensitive)\n")
                        f.write("email=you@example.com\n")
                        f.write("jobs=TEST_ABEND,ANOTHER_JOB\n")

def read_scan_config(config_path):
        cfg = configparser.ConfigParser()
        cfg.read(config_path)
        if 'scan' not in cfg:
                raise SystemExit(f"Missing [scan] section in {config_path}")
        section = cfg['scan']
        folder = section.get('folder', '.')
        return folder

def read_targets(targets_path):
        email = None
        jobs = []
        if not os.path.exists(targets_path):
                raise SystemExit(f"Missing targets file: {targets_path}")
        with open(targets_path, 'r') as f:
                for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                                continue
                        if '=' not in line:
                                continue
                        k, v = line.split('=', 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == 'email':
                                email = v
                        elif k == 'jobs':
                                # Keep @ wildcard intact, convert to uppercase
                                jobs = [j.strip().upper() for j in v.split(',') if j.strip()]
        return email, jobs

def job_matches(job, watch_jobs):
        """
        Check if a job matches any pattern in watch_jobs.
        Supports @ wildcard anywhere: 
        - JOBNAME@ matches JOBNAME*
        - @JOBNAME matches *JOBNAME
        - @JOBNAME@ matches *JOBNAME*
        - JOB@NAME matches JOB*NAME
        """
        if not watch_jobs:
                return True
        
        job_upper = job.upper()
        for pattern in watch_jobs:
                if '@' in pattern:
                        # Convert @ wildcards to regex pattern
                        # Escape any special regex characters except @
                        regex_pattern = re.escape(pattern).replace(r'\@', '.*')
                        # Add anchors for start and end
                        regex_pattern = '^' + regex_pattern + '$'
                        if re.match(regex_pattern, job_upper):
                                return True
                else:
                        # Exact match
                        if job_upper == pattern:
                                return True
        return False

def find_abends(folder, watch_jobs):
        """
        Walk files under folder, extract abend events for jobs in watch_jobs.
        Returns list of dicts: {'dt': datetime, 'month': (num,name), 'job': str, 'sched': str, 'file': str, 'line': str}
        Supports @ wildcard in job patterns (e.g., JOBNAME@ matches JOBNAME*)
        """
        events = []
        if not os.path.exists(folder):
                raise SystemExit(f"Configured folder does not exist: {folder}")
        
        # First pass: count total files to scan
        print("Counting files...", end='', flush=True)
        all_files = []
        for root, dirs, files in os.walk(folder):
                for fname in files:
                        # Only scan files with "TWSMERGE" in the filename
                        if "TWSMERGE" not in fname:
                                continue
                        path = os.path.join(root, fname)
                        # Skip typical binary files by extension heuristics (optional)
                        if any(path.lower().endswith(ext) for ext in ('.zip', '.gz', '.tar', '.jpg', '.png', '.exe', '.dll')):
                                continue
                        all_files.append(path)
        
        total_files = len(all_files)
        print(f" {total_files} files to scan")
        
        if total_files == 0:
                print("No files to scan")
                return events
        
        # Second pass: scan files with progress indicator
        for idx, path in enumerate(all_files, start=1):
                # Calculate and display progress
                progress = (idx / total_files) * 100
                print(f"\rScanning: {progress:5.1f}% ({idx}/{total_files}) - {os.path.basename(path)[:50]:<50}", end='', flush=True)
                
                try:
                        with open(path, 'r', errors='ignore') as fh:
                                for line_no, line in enumerate(fh, start=1):
                                        m = ABEND_RE.search(line)
                                        if not m:
                                                continue
                                        job = m.group('job').upper()
                                        sched = m.group('sched')
                                        date_s = m.group('date')  # dd.mm.yyyy
                                        time_s = m.group('time')  # hh:mm:ss
                                        try:
                                                dt = datetime.strptime(f"{date_s} {time_s}", "%d.%m.%Y %H:%M:%S")
                                        except ValueError:
                                                # skip unparsable date/time
                                                continue
                                        if not job_matches(job, watch_jobs):
                                                continue
                                        events.append({
                                                'dt': dt,
                                                'month': (dt.month, dt.strftime('%B')),
                                                'job': job,
                                                'sched': sched,
                                                'file': path,
                                                'line_no': line_no,
                                                'raw': line.strip()
                                        })
                except (OSError, UnicodeError):
                        # ignore unreadable files
                        continue
        
        print(f"\rScanning: 100.0% ({total_files}/{total_files}) - Complete!{' '*50}")
        print(f"Found {len(events)} matching ABEND event(s)")
        return events

def build_report(events):
        """Return a plain-text report grouped by month in chronological month order."""
        if not events:
                return "No ABEND events found.\n"

        # Group by month number
        groups = {}
        for e in events:
                mnum, mname = e['month']
                groups.setdefault(mnum, {'name': mname, 'items': []})
                groups[mnum]['items'].append(e)

        report_lines = []
        report_lines.append(f"ABEND Report generated: {datetime.now().isoformat()}\n")
        for mnum in sorted(groups.keys()):
                g = groups[mnum]
                report_lines.append(f"In {g['name']} these abends occurred:")
                # sort by datetime
                for e in sorted(g['items'], key=lambda x: x['dt']):
                        dt_s = e['dt'].strftime("%Y-%m-%d %H:%M:%S")
                        report_lines.append(f" - {e['job']} (schedule {e['sched']}) at {dt_s}  -- file: {e['file']}:{e['line_no']}")
                report_lines.append("")  # blank line
        return "\n".join(report_lines)

def send_email_via_mail(to_addr, subject, body):
        """Send email using Linux mail command."""
        # Use mail command (from mailutils or mailx)
        proc = subprocess.Popen(
                ['mail', '-s', subject, to_addr],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(input=body.encode('utf-8'))
        if proc.returncode != 0:
                raise RuntimeError(f"mail command failed: {stderr.decode('utf-8')}")

def main():
        parser = argparse.ArgumentParser(description='Scan files for ABEND events and send report via email')
        parser.add_argument('-c', '--config', 
                          default=os.path.join(SCRIPT_DIR, "scan_config.ini"),
                          help='Path to config file (default: scan_config.ini)')
        parser.add_argument('-t', '--targets',
                          default=os.path.join(SCRIPT_DIR, "targets.cfg"),
                          help='Path to targets file (default: targets.cfg)')
        args = parser.parse_args()
        
        config_path = args.config
        targets_path = args.targets
        
        ensure_config_files(config_path, targets_path)
        folder = read_scan_config(config_path)
        to_email, jobs = read_targets(targets_path)
        if not to_email:
                print(f"No recipient email configured in {targets_path} (email=...). Aborting.")
                sys.exit(1)
        if not jobs:
                print(f"No jobs configured in {targets_path} (jobs=...). Aborting.")
                sys.exit(1)

        watch_jobs = set(jobs)  # uppercase already from read_targets
        events = find_abends(folder, watch_jobs)
        report = build_report(events)
        subject = f"ABEND Report - {datetime.now().date().isoformat()}"
        # Attempt to send email using mail command; on failure, print to stdout
        try:
                send_email_via_mail(to_email, subject, report)
                print(f"Report sent to {to_email}")
        except Exception as exc:
                print("Failed to send email. Printing report to stdout.\n")
                print(report)
                print("\nError sending email:", exc)
                sys.exit(2)

if __name__ == '__main__':
        main()