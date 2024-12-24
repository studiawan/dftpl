# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "USB Device Connected (Registry USBSTOR)"
analyser_category = "User Activity"


def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Windows USB Device Connected (Registry USBSTOR) analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindUSBConnectedUSBSTOR(low_timeline, start_id, end_id)


def FindUSBConnectedUSBSTOR(low_timeline, start_id, end_id):
    """Finds Windows USB Device Connected events based on event structure"""

    # Create a test event to match against

    # Registry Artifacts
    # USBSTOR
    test_event = LowLevelEvent()
    test_event.type = "Content Modification Time-REG"
    test_event.evidence = r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00\d\\Enum\\USBSTOR\\[^\\]+\\[^\\]+\]"

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches_reg_usbstor = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches_reg_usbstor:
        # Extract key values from Evidence
        match = re.search(r"^\[HKEY_LOCAL_MACHINE\\System\\(ControlSet00\d)\\Enum\\USBSTOR\\(.+)\\(.+)\] Address: \[REG_DWORD_LE\] \d+ Capabilities: \[REG_DWORD_LE\] \d+ ClassGUID: \[REG_SZ\] {([a-z0-9\-]+)} CompatibleIDs: \[REG_MULTI_SZ\] .+ ConfigFlags: \[REG_DWORD_LE\] .+ ContainerID: \[REG_SZ\] {([a-z0-9\-]+)} DeviceDesc: \[REG_SZ\] .+ Driver: \[REG_SZ\] {[a-z0-9\-]+}\\(\d+) FriendlyName: \[REG_SZ\] (.+) HardwareID:", each_low_event.evidence)
        control_set = match.group(1)
        reg_key_name = match.group(2)
        reg_sub_key_name = match.group(3)
        class_guid = match.group(4)
        container_id = match.group(5)
        driver_key = match.group(6)
        friendly_name = match.group(7)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "USB Device Connected (Winreg USBSTOR)"
        high_event.description = f"USB device connected with friendly name '{friendly_name}' (Winreg USBSTOR)."
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("ControlSet", control_set)
        high_event.set_keys("RegKeyName", reg_key_name)
        high_event.set_keys("RegSubKeyName", reg_sub_key_name)
        high_event.set_keys("ClassGUID", class_guid)
        high_event.set_keys("ContainerID", container_id)
        high_event.set_keys("DriverKey", driver_key)
        high_event.set_keys("FriendlyName", friendly_name)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"USB device connected with friendly name '{friendly_name}' in 'HKEY_LOCAL_MACHINE\System\\{control_set}\Enum\\USBSTOR\\'."
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://doi.org/10.1016/j.diin.2019.02.004'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline