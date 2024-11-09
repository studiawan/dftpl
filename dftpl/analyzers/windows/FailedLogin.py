# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "Failed Login"
analyser_category = "Windows"


def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Failed Login analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindFailedLogin(low_timeline, start_id, end_id)


def FindFailedLogin(low_timeline, start_id, end_id):
    """Finds Failed Login events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Creation Time-EVT"
    test_event.evidence = r'^\[4625 \/.+\] Provider identifier: {.+} Source Name: Microsoft-Windows-Security-Auditing'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Create dictionary for defining Windows Logon Types values
    logon_title = {
        "2": "Interactive",
        "3": "Network",
        "4": "Batch",
        "5": "Service",
        "7": "Unlock",
        "8": "NetworkCleartext",
        "9": "NewCredentials",
        "10": "RemoteInteractive",
        "11": "CachedInteractive",
    }

    logon_description = {
        "2": "A user logged on to this computer.",
        "3": "A user or computer logged on to this computer from the network.",
        "4": "Batch logon type is used by batch servers, where processes may be executing on behalf of a user without their direct intervention.",
        "5": "A service was started by the Service Control Manager.",
        "7": "This workstation was unlocked.",
        "8": "A user logged on to this computer from the network.",
        "9": "s	A caller cloned its current token and specified new credentials for outbound connections.",
        "10": "A user logged on to this computer remotely using Terminal Services or Remote Desktop.",
        "11": "A user logged on to this computer with network credentials that were stored locally on the computer.",
    }

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        # Extract key values from Evidence
        match = re.search(r"\['(.+?)'  '(.+?)'  '.+?'  '.+?'  '(.+?)'  '(.+?)'  '(.+?)'  '(.+?)'  '.+?'  '(.+?)'  '(.+?)'.+] .+ Record Number: (.+?) ", each_low_event.evidence)
        subject_sid = match.group(1)
        subject_user_name = match.group(2)
        target_user_sid = match.group(3)
        target_user_name = match.group(4)
        target_domain_name = match.group(5)
        status = match.group(6)
        sub_status = match.group(7)
        logon_type = match.group(8)
        record_number = match.group(9)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Failed Login"
        high_event.description = f"Failed login attempt on username '{target_user_name}'"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("SubjectSid", subject_sid)
        high_event.set_keys("SubjectUserName", subject_user_name)
        high_event.set_keys("TargetUserSid", target_user_sid)
        high_event.set_keys("TargetUserName", target_user_name)
        high_event.set_keys("TargetDomainName", target_domain_name)
        high_event.set_keys("Status", status)
        high_event.set_keys("SubStatus", sub_status)
        high_event.set_keys("LogonType", f"{logon_type} - {logon_title[logon_type]} - {logon_description[logon_type]}")
        high_event.set_keys("RecordNumber", record_number)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Failed login attempt on username '{target_user_name}' found with Windows event ID 4625"
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline