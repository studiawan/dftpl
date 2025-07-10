# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "Windows Event Log Cleared"
analyser_category = "User Activity"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Windows Event Log Cleared analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindWindowsEventLogCleared(low_timeline, start_id, end_id)


def FindWindowsEventLogCleared(low_timeline, start_id, end_id):
    """Finds Windows Event Log Cleared events based on event structure"""

    # Create a test event to match against

    # System Log - ID 104
    test_event1 = LowLevelEvent()
    test_event1.type = "Creation Time-EVT"
    test_event1.evidence = r"^\[104 \/.+\] Provider identifier: {.+} Source Name: Microsoft-Windows-Eventlog"

    # Security Log - ID 1102
    test_event2 = LowLevelEvent()
    test_event2.type = "Creation Time-EVT"
    test_event2.evidence = r'^\[1102 \/.+\] Provider identifier: {.+} Source Name: Microsoft-Windows-Eventlog'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches_104 = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event1)
    trigger_matches_1102 = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event2)

    # Extract details from matching events
    for each_low_event in trigger_matches_104:
        # Extract key values from Evidence
        match = re.search(r"\[(?:'(.+?)'|(None))  (?:'(.+?)'|(None))  (?:'(.+?)'|(None))  (?:'(.+?)'|(None))  (?:'(.+?)'|(None))  (?:'(.+?)'|(None))\] Computer Name: (.+) Record Number: (.+?) ", each_low_event.evidence)
        subject_user_name = match.group(1) if match.group(1) else match.group(2)
        subject_domain_name = match.group(3) if match.group(3) else match.group(4)
        channel = match.group(5) if match.group(5) else match.group(6)
        backup_path = match.group(7) if match.group(7) else match.group(8)
        client_process_id = match.group(9) if match.group(9) else match.group(10)
        client_process_start_key = match.group(11) if match.group(11) else match.group(12)
        computer_name = match.group(13)
        record_number = match.group(14)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Windows Event Log Cleared"
        high_event.description = f"Windows Event Log Cleared for '{channel}' log."
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("SubjectUserName", subject_user_name)
        high_event.set_keys("SubjectDomainName", subject_domain_name)
        high_event.set_keys("Channel", channel)
        high_event.set_keys("BackupPath", backup_path)
        high_event.set_keys("ClientProcessId", client_process_id)
        high_event.set_keys("ClientProcessStartKey", client_process_start_key)
        high_event.set_keys("ComputerName", computer_name)
        high_event.set_keys("RecordNumber", record_number)

        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Windows Event Log Cleared for '{channel}' log found in '{each_low_event.path}' with event id '104'."
        reasoning.test_event = test_event1
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://docs.logrhythm.com/devices/docs/v-2-0-evid-104-eventlog-log-file-cleared'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    for each_low_event in trigger_matches_1102:
        # Extract key values from Evidence
        match = re.search(r"\['(.+?)'  '(.+?)'  '(.+?)'  '(.+?)'  '(.+?)'  '(.+?)'\] Computer Name: (.+) Record Number: (.+?) ", each_low_event.evidence)
        subject_user_sid = match.group(1)
        subject_user_name = match.group(2)
        subject_domain_name = match.group(3)
        subject_logon_id = match.group(4)
        client_process_id = match.group(5)
        client_process_start_key = match.group(6)
        computer_name = match.group(7)
        record_number = match.group(8)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Windows Event Log Cleared"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.description = "Windows Event Log Cleared for 'Security' log."
        high_event.set_keys("SubjectUserSid", subject_user_sid)
        high_event.set_keys("SubjectUserName", subject_user_name)
        high_event.set_keys("SubjectDomainName", subject_domain_name)
        high_event.set_keys("SubjectLogonId", subject_logon_id)
        high_event.set_keys("ClientProcessId", client_process_id)
        high_event.set_keys("ClientProcessStartKey", client_process_start_key)
        high_event.set_keys("ComputerName", computer_name)
        high_event.set_keys("RecordNumber", record_number)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Windows Event Log Cleared for 'Security' log found in '{each_low_event.path}' with event id '1102'."
        reasoning.test_event = test_event2
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline