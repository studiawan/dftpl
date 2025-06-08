# dftpl.py 

import argparse
import os
import time
from datetime import datetime
from typing import List
import dftpl.analyzers.yaml.ReadFromYamlAnalyzer as ReadFromYamlAnalyzer
from dftpl.reader.CSVReader import CSVReader
from dftpl.reader.YAMLReader import YAMLReader
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.timelines.HighLevelTimeline import MergeHighLevelTimeline
from dftpl.output.JSONWriter import JSONWriter
from dftpl.rules.Rule import Rule


def format_duration(seconds):
    """Format duration in seconds to human-readable format"""
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    else:
        minutes = int(seconds // 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.2f}s"


# Main function
def main():
    # Start timing the entire process
    total_start_time = time.time()
    start_datetime = datetime.now()
    
    print(f"[{start_datetime.strftime('%Y-%m-%d %H:%M:%S')}] Starting analysis...")
    print("=" * 60)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Forensic event reconstruction tool.")
    parser.add_argument(
        "-i",
        "--input_path",
        action="store",
        required=True,
        type=str,
        help="Path to a CSV file from plaso.",
    )
    parser.add_argument(
        "-o",
        "--output_path",
        action="store",
        required=True,
        type=str,
        help="Output file path.",
    )
    parser.add_argument(
        "-t",
        "--type",
        action="store",
        required=False,
        type=str,
        help="Type of the timeline to create.",
    )

    # Read the arguments from the command line
    args = parser.parse_args()
    input_path = args.input_path
    output_path = args.output_path
    event_type = args.type

    # Read the CSV file
    csv_start_time = time.time()
    print("Reading CSV file ...")
    reader = CSVReader(input_path)
    csv_end_time = time.time()
    print(f"  ✓ CSV reading completed in {format_duration(csv_end_time - csv_start_time)}")

    # Create a list of LowLevelEvent objects
    timeline_start_time = time.time()
    print("Creating low-level timeline ...")
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(reader)
    timeline_end_time = time.time()
    print(f"  ✓ Low-level timeline created with {len(low_timeline.events)} events in {format_duration(timeline_end_time - timeline_start_time)}")

    # Create a list of high-level timeline
    high_timelines = []

    # List of search rules
    # Dictionary mapping event types to rules
    event_analyzers = {
        # Web browsing related events
        "google-search": ["/web/google_search.yml"],
        "bing-search": ["/web/bing_search.yml"],
        "web-visits": ["/web/web_visit.yml"],
        "youtube-watch": ["/web/youtube_watch.yml"],
        "all-web-activity": [
            "/web/google_search.yml",
            "/web/bing_search.yml",
            "/web/web_visit.yml",
            "/web/youtube_watch.yml",
        ],
        # Linux Account Management
        "user-add": [
            "/linux/custom_susp/lnx_user_add.yml",
        ],
        "user-mod": [
            "/linux/custom_susp/lnx_user_mod.yml",
        ],
        "account-management-activity": [
            "/linux/custom_susp/lnx_user_add.yml",
            "/linux/custom_susp/lnx_user_mod.yml",
        ],
        # Authentication related events
        "auth-failure": [
            "/linux/custom_susp/lnx_auth_failure.yml",
        ],
        "session-opened": [
            "/linux/custom_susp/lnx_session_opened.yml",
        ],
        "authentication-activity": [
            "/linux/custom_susp/lnx_auth_failure.yml",
            "/linux/custom_susp/lnx_session_opened.yml",
        ],
        # Web security events
        "web-shell": [
            "/linux/custom_susp/lnx_web_shell_detection.yml",
        ],
        # System log related events
        "security-tools": [
            "/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml"
        ],
        "suspicious-dns": ["/linux/builtin/syslog/lnx_syslog_susp_named.yml"],
        # Cron related events
        "crontab-modification": [
            "/linux/builtin/cron/lnx_cron_crontab_file_modification.yml"
        ],
        # VSFTPD related events
        "ftp-errors": ["/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml"],
        "suspicious-logs": ["/linux/builtin/lnx_shell_susp_log_entries.yml"],
        
        # Comprehensive rule sets
        "all-linux-security": [
            "/linux/custom_susp/lnx_user_add.yml",
            "/linux/custom_susp/lnx_user_mod.yml",
            "/linux/custom_susp/lnx_auth_failure.yml",
            "/linux/custom_susp/lnx_session_opened.yml",
            "/linux/custom_susp/lnx_web_shell_detection.yml",
            "/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml",
            "/linux/builtin/syslog/lnx_syslog_susp_named.yml",
            "/linux/builtin/cron/lnx_cron_crontab_file_modification.yml",
            "/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml",
            "/linux/builtin/lnx_shell_susp_log_entries.yml",
        ],
        
        # Default for running all available rules
        "all": [
            # Web browsing rules
            "/web/google_search.yml",
            "/web/bing_search.yml",
            "/web/web_visit.yml",
            "/web/youtube_watch.yml",
            
            # Linux account management rules
            "/linux/custom_susp/lnx_user_add.yml",
            "/linux/custom_susp/lnx_user_mod.yml",
            
            # Authentication rules
            "/linux/custom_susp/lnx_auth_failure.yml",
            "/linux/custom_susp/lnx_session_opened.yml",
            
            # Web shell rule
            "/linux/custom_susp/lnx_web_shell_detection.yml",
            
            # System security rules
            "/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml",
            "/linux/builtin/syslog/lnx_syslog_susp_named.yml",
            
            # Cron and scheduled task rules
            "/linux/builtin/cron/lnx_cron_crontab_file_modification.yml",
            
            # FTP and service rules
            "/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml",
            
            # General suspicious activity rules
            "/linux/builtin/lnx_shell_susp_log_entries.yml",
        ],
    }
    
    # Default rules - comprehensive set for general analysis
    default_rules = [
        # Core web activity rules
        "/web/google_search.yml",
        "/web/bing_search.yml",
        "/web/web_visit.yml",
        "/web/youtube_watch.yml",
        
        # Core security rules
        "/linux/custom_susp/lnx_user_add.yml",
        "/linux/custom_susp/lnx_user_mod.yml",
        "/linux/custom_susp/lnx_auth_failure.yml",
        "/linux/custom_susp/lnx_session_opened.yml",
        
        # Core system monitoring rules
        "/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml",
        "/linux/builtin/syslog/lnx_syslog_susp_named.yml",
        "/linux/builtin/cron/lnx_cron_crontab_file_modification.yml",
        "/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml",
        "/linux/builtin/lnx_shell_susp_log_entries.yml",
        "/linux/custom_susp/lnx_web_shell_detection.yml",
    ]

    # Get rules based on event_type, or use default rules
    rules = event_analyzers.get(event_type, default_rules)

    # Print information about selected rules
    if event_type:
        print(f"Running analysis with rule set: '{event_type}' ({len(rules)} rules)")
    else:
        print(f"Running analysis with default rule set ({len(rules)} rules)")

    # Read the YAML rules
    rules_start_time = time.time()
    print("Loading YAML rules ...")
    yaml_contents: List[Rule] = []
    for rule in rules:
        yaml_file_path = os.path.join(os.path.dirname(__file__), "rules" + rule)
        
        # Check if rule file exists
        if not os.path.exists(yaml_file_path):
            print(f"Warning: Rule file not found: {yaml_file_path}")
            continue
            
        try:
            reader = YAMLReader(yaml_file_path)
            yaml_content = reader.read()
            yaml_contents.append(yaml_content)
            print(f"  ✓ Loaded rule: {rule}")
        except Exception as e:
            print(f"  ✗ Error loading rule {rule}: {str(e)}")
            continue

    rules_end_time = time.time()
    print(f"  ✓ Loaded {len(yaml_contents)} rules in {format_duration(rules_end_time - rules_start_time)}")

    if not yaml_contents:
        print("Error: No valid rules could be loaded. Exiting.")
        return

    # Run each rules with the analyzer
    analysis_start_time = time.time()
    print(f"Running {len(yaml_contents)} rules against the timeline...")
    total_events_found = 0
    
    for i, yaml_content in enumerate(yaml_contents, 1):            
        rule_start_time = time.time()
        print(f"[{i}/{len(yaml_contents)}] Processing rule: {yaml_content.title} ...")
        
        try:
            high_timeline = ReadFromYamlAnalyzer.Run(low_timeline, yaml_content)
            rule_end_time = time.time()
            
            if high_timeline and len(high_timeline.events) > 0:
                high_timelines.append(high_timeline)
                events_count = len(high_timeline.events)
                total_events_found += events_count
                print(f"  ✓ Found {events_count} events in {format_duration(rule_end_time - rule_start_time)}")
            else:
                print(f"  ○ No events found in {format_duration(rule_end_time - rule_start_time)}")
        except Exception as e:
            rule_end_time = time.time()
            print(f"  ✗ Error processing rule in {format_duration(rule_end_time - rule_start_time)}: {str(e)}")
            continue

    analysis_end_time = time.time()
    print(f"  ✓ Rule analysis completed in {format_duration(analysis_end_time - analysis_start_time)}")
    print(f"  ✓ Total events found: {total_events_found}")

    if not high_timelines:
        print("No events were detected by any rules.")
        total_end_time = time.time()
        print(f"\nTotal execution time: {format_duration(total_end_time - total_start_time)}")
        return

    # Merge the high-level timelines
    merge_start_time = time.time()
    print("Merging high-level timelines ...")
    merge_timelines = MergeHighLevelTimeline(high_timelines)
    merged_high_timelines = merge_timelines.merge()
    merge_end_time = time.time()
    print(f"  ✓ Timeline merging completed in {format_duration(merge_end_time - merge_start_time)}")

    # Write the results to a JSON file
    output_start_time = time.time()
    print(f"Writing results to JSON file: {output_path} ...")
    print(f"Total events in merged timeline: {len(merged_high_timelines.events)}")
    json_writer = JSONWriter(merged_high_timelines, output_path)
    json_writer.write()
    output_end_time = time.time()
    print(f"  ✓ JSON output completed in {format_duration(output_end_time - output_start_time)}")
    
    # Calculate and display total execution time
    total_end_time = time.time()
    total_duration = total_end_time - total_start_time
    end_datetime = datetime.now()
    
    print("=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Start time:          {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"End time:            {end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total duration:      {format_duration(total_duration)}")
    print(f"Input events:        {len(low_timeline.events):,}")
    print(f"Rules processed:     {len(yaml_contents)}")
    print(f"Output events:       {len(merged_high_timelines.events):,}")
    print(f"Processing rate:     {len(low_timeline.events)/total_duration:.0f} events/second")
    print("=" * 60)
    print("Analysis completed successfully!")

