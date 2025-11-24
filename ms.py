#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import argparse
import csv
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

# Regex to extract time, date, server, schedule, job from ABEND lines.
# Handles both formats: SERVER#SCHEDULE[...].JOB and SCHEDULE[...].JOB
ABEND_RE = re.compile(
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<date>\d{2}\.\d{2}\.\d{4}).*?following job has stopped unexpectedly:\s+'
        r'(?:(?P<server>\w+)#)?(?P<sched>[^\[\].\s#]+)\[.*?\]\.(?P<job>[^\s(]+)',
        re.IGNORECASE
)

# Regex for successful job completion
# Example: 07:01:39 24.11.2025|BATCHMAN:Job VEL3009LAM#JOBS[(0731 11/23/25),(JOBS)].LS (#J1138883) has completed SUCCESSFULLY
SUCCESS_RE = re.compile(
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<date>\d{2}\.\d{2}\.\d{4}).*?Job\s+(?P<server>\w+)#(?P<sched>[^\[\].\s]+)\[.*?\]\.(?P<job>[^\s(]+)\s+.*?has completed SUCCESSFULLY',
        re.IGNORECASE
)

# Regex for job execution start
# Example: 07:01:39 24.11.2025|BATCHMAN:AWSBHT075I Changing job stream JOBS[(0731 11/23/25),(JOBS)] status to EXEC.
START_RE = re.compile(
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<date>\d{2}\.\d{2}\.\d{4}).*?Changing job stream\s+(?P<sched>[^\[\].\s]+)\[.*?\]\s+status to EXEC',
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
                        f.write("# jobs= comma-separated list of job names to report (case-insensitive, supports @ wildcard)\n")
                        f.write("# abend= Yes to include abend events in report (default: Yes)\n")
                        f.write("# success= Yes to include success events in report (default: No)\n")
                        f.write("# report_period= Daily, Weekly, or Monthly - filters events by timeframe (default: Monthly)\n")
                        f.write("email=you@example.com\n")
                        f.write("jobs=TEST_ABEND,ANOTHER_JOB\n")
                        f.write("abend=Yes\n")
                        f.write("success=No\n")
                        f.write("report_period=Monthly\n")

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
        include_abend = True  # default
        include_success = False  # default
        report_period = 'monthly'  # default
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
                        elif k == 'abend':
                                include_abend = v.lower() in ('yes', 'true', '1')
                        elif k == 'success':
                                include_success = v.lower() in ('yes', 'true', '1')
                        elif k == 'report_period':
                                rp = v.lower()
                                if rp in ('daily', 'weekly', 'monthly'):
                                        report_period = rp
                                else:
                                        print(f"Warning: Invalid report_period '{v}', using 'monthly'")
        return email, jobs, include_abend, include_success, report_period

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

def scan_events(folder, watch_jobs, track_abends=True, track_successes=False):
        """
        Walk files under folder, extract abend and/or success events for jobs in watch_jobs.
        Returns tuple: (abend_events, success_events)
        Each is a list of dicts: {'dt': datetime, 'month': (num,name), 'job': str, 'sched': str, 'file': str, 'line': str, 'start_time': datetime, 'runtime': str}
        Supports @ wildcard in job patterns (e.g., JOBNAME@ matches JOBNAME*)
        """
        abend_events = []
        success_events = []
        # Track schedule start times: key = sched, value = datetime
        job_start_times = {}
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
                return abend_events, success_events
        
        # Second pass: scan files with progress indicator
        for idx, path in enumerate(all_files, start=1):
                # Calculate and display progress
                progress = (idx / total_files) * 100
                print(f"\rScanning: {progress:5.1f}% ({idx}/{total_files}) - {os.path.basename(path)[:50]:<50}", end='', flush=True)
                
                try:
                        with open(path, 'r', errors='ignore') as fh:
                                for line_no, line in enumerate(fh, start=1):
                                        # Check for job START events (always track for runtime calculation)
                                        m_start = START_RE.search(line)
                                        if m_start:
                                                sched = m_start.group('sched')
                                                date_s = m_start.group('date')
                                                time_s = m_start.group('time')
                                                try:
                                                        dt = datetime.strptime(f"{date_s} {time_s}", "%d.%m.%Y %H:%M:%S")
                                                        # Store start time keyed by schedule only
                                                        job_start_times[sched] = dt
                                                except ValueError:
                                                        pass
                                        
                                        # Check for ABEND events
                                        if track_abends:
                                                m = ABEND_RE.search(line)
                                                if m:
                                                        job = m.group('job').upper()
                                                        sched = m.group('sched')
                                                        server = m.group('server') if m.group('server') else ''
                                                        date_s = m.group('date')  # dd.mm.yyyy
                                                        time_s = m.group('time')  # hh:mm:ss
                                                        try:
                                                                dt = datetime.strptime(f"{date_s} {time_s}", "%d.%m.%Y %H:%M:%S")
                                                        except ValueError:
                                                                continue
                                                        if not job_matches(job, watch_jobs):
                                                                continue
                                                        
                                                        # Calculate runtime if start time exists for this schedule
                                                        start_time = job_start_times.get(sched)
                                                        runtime = None
                                                        if start_time:
                                                                duration = dt - start_time
                                                                runtime = str(duration).split('.')[0]  # Remove microseconds
                                                        
                                                        abend_events.append({
                                                                'dt': dt,
                                                                'month': (dt.month, dt.strftime('%B')),
                                                                'job': job,
                                                                'sched': sched,
                                                                'server': server,
                                                                'file': path,
                                                                'line_no': line_no,
                                                                'raw': line.strip(),
                                                                'start_time': start_time,
                                                                'runtime': runtime
                                                        })
                                        
                                        # Check for SUCCESS events
                                        if track_successes:
                                                m = SUCCESS_RE.search(line)
                                                if m:
                                                        job = m.group('job').upper()
                                                        sched = m.group('sched')
                                                        server = m.group('server')
                                                        date_s = m.group('date')
                                                        time_s = m.group('time')
                                                        try:
                                                                dt = datetime.strptime(f"{date_s} {time_s}", "%d.%m.%Y %H:%M:%S")
                                                        except ValueError:
                                                                continue
                                                        if not job_matches(job, watch_jobs):
                                                                continue
                                                        
                                                        # Calculate runtime if start time exists for this schedule
                                                        start_time = job_start_times.get(sched)
                                                        runtime = None
                                                        if start_time:
                                                                duration = dt - start_time
                                                                runtime = str(duration).split('.')[0]  # Remove microseconds
                                                        
                                                        success_events.append({
                                                                'dt': dt,
                                                                'month': (dt.month, dt.strftime('%B')),
                                                                'job': job,
                                                                'sched': sched,
                                                                'server': server,
                                                                'file': path,
                                                                'line_no': line_no,
                                                                'raw': line.strip(),
                                                                'start_time': start_time,
                                                                'runtime': runtime
                                                        })
                except (OSError, UnicodeError):
                        # ignore unreadable files
                        continue
        
        print(f"\rScanning: 100.0% ({total_files}/{total_files}) - Complete!{' '*50}")
        if track_abends:
                print(f"Found {len(abend_events)} ABEND event(s)")
        if track_successes:
                print(f"Found {len(success_events)} SUCCESS event(s)")
        return abend_events, success_events

def build_report(abend_events, success_events):
        """Return a plain-text report grouped by month in chronological month order."""
        report_lines = []
        report_lines.append(f"Job Events Report generated: {datetime.now().isoformat()}\n")
        
        # Report ABEND events
        if abend_events:
                report_lines.append("=" * 70)
                report_lines.append("ABEND EVENTS")
                report_lines.append("=" * 70)
                groups = {}
                for e in abend_events:
                        mnum, mname = e['month']
                        groups.setdefault(mnum, {'name': mname, 'items': []})
                        groups[mnum]['items'].append(e)
                
                for mnum in sorted(groups.keys()):
                        g = groups[mnum]
                        report_lines.append(f"\nIn {g['name']} these abends occurred:")
                        for e in sorted(g['items'], key=lambda x: x['dt']):
                                dt_s = e['dt'].strftime("%Y-%m-%d %H:%M:%S")
                                server = e.get('server', '')
                                sched_info = f"{e['sched']}#{server}" if server else e['sched']
                                report_lines.append(f" - {e['job']} (schedule {sched_info}) at {dt_s}")
                report_lines.append("")
        
        # Report SUCCESS events
        if success_events:
                report_lines.append("=" * 70)
                report_lines.append("SUCCESS EVENTS")
                report_lines.append("=" * 70)
                groups = {}
                for e in success_events:
                        mnum, mname = e['month']
                        groups.setdefault(mnum, {'name': mname, 'items': []})
                        groups[mnum]['items'].append(e)
                
                for mnum in sorted(groups.keys()):
                        g = groups[mnum]
                        report_lines.append(f"\nIn {g['name']} these successes occurred:")
                        for e in sorted(g['items'], key=lambda x: x['dt']):
                                dt_s = e['dt'].strftime("%Y-%m-%d %H:%M:%S")
                                server = e.get('server', '')
                                sched_info = f"{e['sched']}#{server}" if server else e['sched']
                                report_lines.append(f" - {e['job']} (schedule {sched_info}) at {dt_s}")
                report_lines.append("")
        
        if not abend_events and not success_events:
                report_lines.append("No events found.\n")
        
        return "\n".join(report_lines)

def append_to_log(log_path, events, event_type):
        """Append events to a daily log file with deduplication based on core event identity."""
        # Read existing events and track by core identity (timestamp|job|schedule|server)
        existing_events = {}  # key: core_id, value: full line
        if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                        for line in f:
                                line = line.strip()
                                if not line:
                                        continue
                                parts = line.split('|')
                                if len(parts) >= 4:
                                        # Core identity: timestamp|job|schedule|server
                                        core_id = f"{parts[0]}|{parts[1]}|{parts[2]}|{parts[3]}"
                                        # Keep the entry with runtime if it exists, otherwise the first one
                                        if core_id not in existing_events or (len(parts) > 5 and parts[5]):
                                                existing_events[core_id] = line
        
        # Write back all events (existing + new unique ones)
        new_count = 0
        with open(log_path, 'w') as f:
                # Write existing events first
                for line in existing_events.values():
                        f.write(line + "\n")
                
                # Add new unique events
                for e in events:
                        dt_s = e['dt'].strftime("%Y-%m-%d %H:%M:%S")
                        server = e.get('server', '')
                        start_time_s = e['start_time'].strftime("%Y-%m-%d %H:%M:%S") if e.get('start_time') else ''
                        runtime = e.get('runtime', '')
                        
                        # Core identity for deduplication
                        core_id = f"{dt_s}|{e['job']}|{e['sched']}|{server}"
                        
                        # Format: timestamp|job|schedule|server|start_time|runtime|file:line
                        log_line = f"{dt_s}|{e['job']}|{e['sched']}|{server}|{start_time_s}|{runtime}|{e['file']}:{e['line_no']}"
                        
                        # Only add if not already existing, or if this one has runtime and existing doesn't
                        if core_id not in existing_events:
                                f.write(log_line + "\n")
                                existing_events[core_id] = log_line
                                new_count += 1
                        elif runtime and core_id in existing_events:
                                # Update existing entry if new one has runtime data
                                existing_line = existing_events[core_id]
                                existing_parts = existing_line.split('|')
                                if len(existing_parts) <= 5 or not existing_parts[5]:
                                        # Replace the existing entry without runtime
                                        new_count += 1
        
        return new_count

def filter_events_by_period(events, period):
        """Filter events to only include those within the specified time period."""
        if not events:
                return events
        
        now = datetime.now()
        
        if period == 'daily':
                # Last 24 hours
                cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'weekly':
                # Last 7 days
                cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
                cutoff = cutoff.replace(day=cutoff.day - 7) if cutoff.day > 7 else cutoff.replace(month=cutoff.month - 1 if cutoff.month > 1 else 12, day=cutoff.day + 23, year=cutoff.year if cutoff.month > 1 else cutoff.year - 1)
        elif period == 'monthly':
                # Current month
                cutoff = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
                # Default: no filtering
                return events
        
        filtered = [e for e in events if e['dt'] >= cutoff]
        return filtered

def read_log_events(log_path, event_type):
        """Read events from daily log file."""
        events = []
        if not os.path.exists(log_path):
                return events
        
        with open(log_path, 'r') as f:
                for line in f:
                        line = line.strip()
                        if not line:
                                continue
                        parts = line.split('|')
                        if len(parts) < 4:
                                continue
                        
                        try:
                                # Format: timestamp|job|schedule|server|start_time|runtime|file:line
                                dt = datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S")
                                job = parts[1]
                                sched = parts[2]
                                server = parts[3] if len(parts) > 6 else ''
                                start_time_s = parts[4] if len(parts) > 6 else ''
                                runtime = parts[5] if len(parts) > 6 else ''
                                file_info = parts[6] if len(parts) > 6 else parts[3]
                                
                                # Handle old log format where schedule might contain CPU#SCHEDULE
                                if '#' in sched and not server:
                                        parts_sched = sched.split('#', 1)
                                        server = parts_sched[0]
                                        sched = parts_sched[1]
                                
                                start_time = None
                                if start_time_s:
                                        try:
                                                start_time = datetime.strptime(start_time_s, "%Y-%m-%d %H:%M:%S")
                                        except ValueError:
                                                pass
                                
                                event = {
                                        'dt': dt,
                                        'month': (dt.month, dt.strftime('%B')),
                                        'job': job,
                                        'sched': sched,
                                        'file': file_info,
                                        'line_no': 0,
                                        'start_time': start_time,
                                        'runtime': runtime if runtime else None
                                }
                                
                                # Add server info for all events
                                if server:
                                        event['server'] = server
                                
                                events.append(event)
                        except (ValueError, IndexError):
                                continue
        
        return events

def create_csv_report(abend_events, success_events, csv_path):
        """Create a CSV file with all events in spreadsheet format."""
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['CPU', 'Schedule', 'Job', 'State', 'Start Time', 'End Time', 'Runtime'])
                
                # Write ABEND events
                for e in sorted(abend_events, key=lambda x: x['dt']):
                        cpu = e.get('server', '')  # ABEND events may not have server, use empty
                        schedule = e['sched']
                        job = e['job']
                        state = 'ABEND'
                        start_time = e.get('start_time').strftime("%Y-%m-%d %H:%M:%S") if e.get('start_time') else ''
                        end_time = e['dt'].strftime("%Y-%m-%d %H:%M:%S")
                        runtime = e.get('runtime', '')
                        writer.writerow([cpu, schedule, job, state, start_time, end_time, runtime])
                
                # Write SUCCESS events
                for e in sorted(success_events, key=lambda x: x['dt']):
                        cpu = e.get('server', '')
                        schedule = e['sched']
                        job = e['job']
                        state = 'SUCCESS'
                        start_time = e.get('start_time').strftime("%Y-%m-%d %H:%M:%S") if e.get('start_time') else ''
                        end_time = e['dt'].strftime("%Y-%m-%d %H:%M:%S")
                        runtime = e.get('runtime', '')
                        writer.writerow([cpu, schedule, job, state, start_time, end_time, runtime])
        
        return csv_path

def send_email_via_mail(to_addr, subject, body, attachment=None):
        """Send email using Linux mail command with optional attachment."""
        if attachment and os.path.exists(attachment):
                # Use mailx format with -a for attachment (most common)
                proc = subprocess.Popen(
                        ['mail', '-s', subject, '-a', attachment, to_addr],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                )
                stdout, stderr = proc.communicate(input=body.encode('utf-8'))
                if proc.returncode != 0:
                        raise RuntimeError(f"mail command failed: {stderr.decode('utf-8')}")
        else:
                # Use mail command without attachment
                proc = subprocess.Popen(
                        ['mail', '-s', subject, to_addr],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                )
                stdout, stderr = proc.communicate(input=body.encode('utf-8'))
                if proc.returncode != 0:
                        raise RuntimeError(f"mail command failed: {stderr.decode('utf-8')}")

def send_email_via_mail_legacy(to_addr, subject, body):
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
        parser = argparse.ArgumentParser(description='Scan files for ABEND and SUCCESS events and send report via email')
        parser.add_argument('-c', '--config', 
                          default=os.path.join(SCRIPT_DIR, "scan_config.ini"),
                          help='Path to config file (default: scan_config.ini)')
        parser.add_argument('-t', '--targets',
                          default=os.path.join(SCRIPT_DIR, "targets.cfg"),
                          help='Path to targets file (default: targets.cfg)')
        parser.add_argument('-d', '--daily', action='store_true',
                          help='Daily mode: scan and append to log files without sending email')
        args = parser.parse_args()
        
        config_path = args.config
        targets_path = args.targets
        daily_mode = args.daily
        
        ensure_config_files(config_path, targets_path)
        folder = read_scan_config(config_path)
        to_email, jobs, include_abend, include_success, report_period = read_targets(targets_path)
        
        if not jobs:
                print(f"No jobs configured in {targets_path} (jobs=...). Aborting.")
                sys.exit(1)
        
        watch_jobs = set(jobs)  # uppercase already from read_targets
        
        # Daily mode: scan and log to files
        if daily_mode:
                abend_log = os.path.join(SCRIPT_DIR, "abends.log")
                success_log = os.path.join(SCRIPT_DIR, "successes.log")
                
                print("Running in daily logging mode...")
                abend_events, success_events = scan_events(folder, watch_jobs, True, True)
                
                abend_count = append_to_log(abend_log, abend_events, 'abend')
                success_count = append_to_log(success_log, success_events, 'success')
                
                print(f"Logged {abend_count} new ABEND event(s) to {abend_log}")
                print(f"Logged {success_count} new SUCCESS event(s) to {success_log}")
                return
        
        # Report mode: use log files or scan directly
        if not to_email:
                print(f"No recipient email configured in {targets_path} (email=...). Aborting.")
                sys.exit(1)
        
        abend_events = []
        success_events = []
        
        # Try to read from log files first
        abend_log = os.path.join(SCRIPT_DIR, "abends.log")
        success_log = os.path.join(SCRIPT_DIR, "successes.log")
        
        if os.path.exists(abend_log) or os.path.exists(success_log):
                print("Reading from log files...")
                if include_abend:
                        abend_events = read_log_events(abend_log, 'abend')
                        print(f"Loaded {len(abend_events)} ABEND event(s) from log")
                if include_success:
                        success_events = read_log_events(success_log, 'success')
                        print(f"Loaded {len(success_events)} SUCCESS event(s) from log")
        else:
                # Scan directly if no log files exist
                print("No log files found, scanning directly...")
                abend_events, success_events = scan_events(folder, watch_jobs, include_abend, include_success)
        
        # Filter events based on config
        if not include_abend:
                abend_events = []
        if not include_success:
                success_events = []
        
        # Filter by time period
        abend_events = filter_events_by_period(abend_events, report_period)
        success_events = filter_events_by_period(success_events, report_period)
        
        print(f"Generating {report_period.capitalize()} report...")
        report = build_report(abend_events, success_events)
        subject = f"Job Events Report ({report_period.capitalize()}) - {datetime.now().date().isoformat()}"
        
        # Create CSV file
        csv_path = os.path.join(SCRIPT_DIR, f"job_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        try:
                create_csv_report(abend_events, success_events, csv_path)
                print(f"CSV report created: {csv_path}")
        except Exception as exc:
                print(f"Warning: Failed to create CSV: {exc}")
                csv_path = None
        
        # Attempt to send email using mail command; on failure, print to stdout
        try:
                send_email_via_mail(to_email, subject, report, csv_path)
                print(f"Report sent to {to_email}" + (f" with attachment {os.path.basename(csv_path)}" if csv_path else ""))
        except Exception as exc:
                print("Failed to send email. Printing report to stdout.\n")
                print(report)
                print("\nError sending email:", exc)
                if csv_path and os.path.exists(csv_path):
                        print(f"\nCSV file available at: {csv_path}")
                sys.exit(2)

if __name__ == '__main__':
        main()