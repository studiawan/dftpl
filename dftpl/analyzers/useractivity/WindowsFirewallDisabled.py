# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "Windows Firewall Disabled"
analyser_category = "User Activity"


def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Windows Firewall Disabled analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindWindowsFirewallDisabled(low_timeline, start_id, end_id)


def FindWindowsFirewallDisabled(low_timeline, start_id, end_id):
    """Finds Windows Firewall Disabled events based on event structure"""

    # Create a test event to match against
    test_event1 = LowLevelEvent()
    test_event1.type = "Content Modification Time-EVT"
    test_event1.evidence = r"^\[2082.*?\].+Source Name: Microsoft-Windows-Windows Firewall With Advanced Security Strings: \['[124]'  '1'  '.+?'  '.+?'  'No'"

    test_event2 = LowLevelEvent()
    test_event2.type = "Content Modification Time-REG"
    test_event2.evidence = r'Services\\SharedAccess\\Parameters\\FirewallPolicy\\(?:Standard|Public|Domain)Profile\]'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Create dictionary for defining firewall profile values
    profile_val_evt = {
        "1": "Domain",
        "2": "Private",
        "4": "Public"
    }

    # Find matching events
    trigger_matches_evt = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event1)
    trigger_matches_reg = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event2)

    # Extract details from matching events
    for each_low_event in trigger_matches_evt:
        # Extract key values from Evidence
        match = re.search(r"\['([124])'  '.+?'  '.+?'  '.+?'  '.+?'  '(.+?)'  '(.+?)'  '(.+?)'  '(.+?)'] Computer Name: (.+) Record Number: (.+?) ", each_low_event.evidence)
        profiles = match.group(1)
        origin = match.group(2)
        modifying_user = match.group(3)
        modifying_app = match.group(4)
        error_code = match.group(5)
        computer_name = match.group(6)
        record_number = match.group(7)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Windows Firewall Disabled"
        high_event.description = f"Windows Firewall disabled for '{profile_val_evt[profiles]}' profile (Windows Event Log)."
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("Profiles", profiles)
        high_event.set_keys("Origin", origin)
        high_event.set_keys("ModifyingUser", modifying_user)
        high_event.set_keys("ModifyingApplication", modifying_app)
        high_event.set_keys("ErrorCode", error_code)
        high_event.set_keys("ComputerName", computer_name)
        high_event.set_keys("RecordNumber", record_number)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Windows Firewall disabled event found for '{profile_val_evt[profiles]}' profile in '{each_low_event.path}' with event id '2082'."
        reasoning.test_event = test_event1
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://detection.fyi/sigmahq/sigma/windows/builtin/firewall_as/win_firewall_as_setting_change/'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    for each_low_event in trigger_matches_reg:
        # Extract key values from Evidence
        match = re.search(r"\[(.+\\)(Standard|Public|Domain)Profile\] DisableNotifications: \[REG_DWORD_LE\] (.+) EnableFirewall: \[REG_DWORD_LE\] (.+)$", each_low_event.evidence)
        path_frag = match.group(1)
        profiles = match.group(2)
        disable_notif = match.group(3)
        enable_firewall = match.group(4)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Windows Firewall Disabled"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        if profiles == "Standard":
            high_event.set_keys("Profiles", "Private")
        else :
            high_event.set_keys("Profiles", profiles)
        high_event.description = f"Windows Firewall disabled for '{high_event.keys["Profiles"]}' profile (Windows Registry)."
        high_event.set_keys("DisableNotifications", disable_notif)
        high_event.set_keys("EnableFirewall", enable_firewall)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Windows Firewall disabled event found for '{high_event.keys["Profiles"]}' profile from changes to '{path_frag + profiles + "Profile"}' registry key."
        reasoning.test_event = test_event2
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://blogs.cisco.com/security/talos/opening-zxshell'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline