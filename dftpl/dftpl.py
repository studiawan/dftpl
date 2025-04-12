import argparse
import os
import dftpl.analyzers.yaml.ReadFromYamlAnalyzer as ReadFromYamlAnalyzer
from dftpl.reader.CSVReader import CSVReader
from dftpl.reader.YAMLReader import YAMLReader
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.timelines.HighLevelTimeline import MergeHighLevelTimeline
from dftpl.output.JSONWriter import JSONWriter


# Main function
def main():
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
    print("Reading CSV file ...")
    reader = CSVReader(input_path)

    # Create a list of LowLevelEvent objects
    print("Creating low-level timeline ...")
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(reader)

    # Create a list of high-level timeline
    high_timelines = []

    # List of search rules
    # Dictionary mapping event types to rules
    event_analyzers = {
        # Web browsing related events
        "google-search": ["/web/GoogleSearch.yml", "/web/GoogleSearch_regex.yml"],
        "bing-search": ["/web/BingSearch.yml", "/web/BingSearch_regex.yml"],
        "web-visits": ["/web/WebVisit.yml", "/web/WebVisit_regex.yml"],
        "images-cached": ["/web/AllImagesFromCache.yml", "/web/AllImagesFromCache_regex.yml"],
        "videos-cached": ["/web/AllVideosFromCache.yml", "/web/AllVideosFromCache_regex.yml"],
        "all-web-activity": [
            "/web/GoogleSearch.yml", "/web/GoogleSearch_regex.yml",
            "/web/BingSearch.yml", "/web/BingSearch_regex.yml",
            "/web/WebVisit.yml", "/web/WebVisit_regex.yml",
            "/web/AllImagesFromCache.yml", "/web/AllImagesFromCache_regex.yml",
            "/web/AllVideosFromCache.yml", "/web/AllVideosFromCache_regex.yml"
        ],
        
        # System log related events
        "security-tools": ["/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml"],
        "suspicious-dns": ["/builtin/syslog/lnx_syslog_susp_named.yml"],
        "system-logs": [
            "/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml", 
            "/builtin/syslog/lnx_syslog_susp_named.yml"
        ],
        
        # Cron related events
        "crontab-modification": ["/builtin/cron/lnx_cron_crontab_file_modification.yml"],
        
        # VSFTPD related events
        "ftp-errors": ["/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml"],
        "suspicious-logs": ["/builtin/vsftpd/lnx_shell_susp_log_entries.yml"],
        
        # Custom suspicious activities
        "file-access": ["/custom_susp/lnx_file_access_or_modification.yml"],
        "privilege-escalation": ["/custom_susp/lnx_privilege_escalation_detection.yml"],
        "ssh-brute-force": ["/custom_susp/lnx_ssh_brute_force_attempts.yml"],
        "suspicious-user": ["/custom_susp/lnx_suspicious_user_account_creation.yml"],
        "web-shell": ["/custom_susp/lnx_web_shell_detection.yml"],
        "suspicious-activity": [
            "/custom_susp/lnx_file_access_or_modification.yml",
            "/custom_susp/lnx_privilege_escalation_detection.yml",
            "/custom_susp/lnx_ssh_brute_force_attempts.yml",
            "/custom_susp/lnx_suspicious_user_account_creation.yml",
            "/custom_susp/lnx_web_shell_detection.yml"
        ],
        
        # Combined categories
        "security-monitoring": [
            "/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml",
            "/builtin/syslog/lnx_syslog_susp_named.yml",
            "/custom_susp/lnx_privilege_escalation_detection.yml",
            "/custom_susp/lnx_ssh_brute_force_attempts.yml",
            "/custom_susp/lnx_suspicious_user_account_creation.yml",
            "/custom_susp/lnx_web_shell_detection.yml"
        ],
        
        # All Linux-specific events
        "all-linux-events": [
            "/builtin/cron/lnx_cron_crontab_file_modification.yml",
            "/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml",
            "/builtin/syslog/lnx_syslog_susp_named.yml",
            "/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml",
            "/builtin/vsftpd/lnx_shell_susp_log_entries.yml",
            "/custom_susp/lnx_file_access_or_modification.yml",
            "/custom_susp/lnx_privilege_escalation_detection.yml",
            "/custom_susp/lnx_ssh_brute_force_attempts.yml",
            "/custom_susp/lnx_suspicious_user_account_creation.yml",
            "/custom_susp/lnx_web_shell_detection.yml"
        ],
        
        # Default for running all available rules
        "all": [
            # Web rules
            "/web/GoogleSearch.yml", "/web/GoogleSearch_regex.yml",
            "/web/BingSearch.yml", "/web/BingSearch_regex.yml",
            "/web/WebVisit.yml", "/web/WebVisit_regex.yml",
            "/web/AllImagesFromCache.yml", "/web/AllImagesFromCache_regex.yml",
            "/web/AllVideosFromCache.yml", "/web/AllVideosFromCache_regex.yml",
            
            # Linux rules
            "/builtin/cron/lnx_cron_crontab_file_modification.yml",
            "/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml",
            "/builtin/syslog/lnx_syslog_susp_named.yml",
            "/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml",
            "/builtin/vsftpd/lnx_shell_susp_log_entries.yml",
            "/custom_susp/lnx_file_access_or_modification.yml",
            "/custom_susp/lnx_privilege_escalation_detection.yml",
            "/custom_susp/lnx_ssh_brute_force_attempts.yml",
            "/custom_susp/lnx_suspicious_user_account_creation.yml",
            "/custom_susp/lnx_web_shell_detection.yml"
        ]
    }
    # Default rules
    default_rules = ["/web/GoogleSearch.yml"]

    # Get rules based on event_type, or use default rules
    rules = event_analyzers.get(event_type, default_rules)

    # Read the YAML rules
    yaml_contents = []
    for rule in rules:
        yaml_file_path = os.path.join(os.path.dirname(__file__), "rules" + rule)
        reader = YAMLReader(yaml_file_path)
        yaml_content = reader.read()
        yaml_contents.append(yaml_content)

    # Run each rules with the analyzer
    for yaml_content in yaml_contents:
        high_timeline = ReadFromYamlAnalyzer.Run(low_timeline, yaml_content)
        if high_timeline:
            high_timelines.append(high_timeline)

    # Merge the high-level timelines
    print("Merging high-level timelines ...")
    merge_timelines = MergeHighLevelTimeline(high_timelines)
    merged_high_timelines = merge_timelines.merge()

    # Write the results to a JSON file
    print(f"Writing results to JSON file: {output_path} ...")
    json_writer = JSONWriter(merged_high_timelines, output_path)
    json_writer.write()
