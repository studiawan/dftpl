# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "USB Device Connected (Registry USB)"
analyser_category = "User Activity"


def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Windows USB Device Connected analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindUSBConnectedRegUSB(low_timeline, start_id, end_id)


def FindUSBConnectedRegUSB(low_timeline, start_id, end_id):
    """Finds Windows USB Device Connected events based on event structure"""

    # Create a test event to match against

    # Registry Artifacts
    # USB
    test_event = LowLevelEvent()
    test_event.type = "Last Connection Time-REG"
    test_event.evidence = r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00\d\\Enum\\USB] Product: PID_"

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches_reg_usb = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches_reg_usb:
        # Extract key values from Evidence
        match = re.search(r"^\[HKEY_LOCAL_MACHINE\\System\\(ControlSet00\d)\\Enum\\USB] Product: PID_(.+) Serial: (.+) Subkey name: (VID_(.+)&PID_.+) Vendor:", each_low_event.evidence)
        control_set = match.group(1)
        pid = match.group(2)
        serial = match.group(3)
        subkey_name = match.group(4)
        vid = match.group(5)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "USB Device Connected"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.description = f"USB device connected with Vendor ID '{vid}' and Product ID '{pid}' (Winreg USB)."
        high_event.set_keys("ControlSet", control_set)
        high_event.set_keys("VID", vid)
        high_event.set_keys("PID", pid)
        high_event.set_keys("Subkey name", subkey_name)
        high_event.set_keys("Serial", serial)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"USB device connected with VID '{vid}' and PID '{pid}' in 'HKEY_LOCAL_MACHINE\System\\{control_set}\\Enum\\USB'."
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://doi.org/10.1016/j.diin.2019.02.004'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)


    return high_timeline