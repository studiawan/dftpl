# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "USB Device Connected (Registry DeviceClasses)"
analyser_category = "User Activity"


def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Windows USB Device Connected (Registry DeviceClasses) analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindUSBConnectedDeviceClasses(low_timeline, start_id, end_id)


def FindUSBConnectedDeviceClasses(low_timeline, start_id, end_id):
    """Finds Windows USB Device Connected events based on event structure"""

    # Create a test event to match against

    # Registry Artifacts
    # DeviceClasses (Using entry from device interface class 'GUID_DEVINTERFACE_USB_DEVICE')
    test_event = LowLevelEvent()
    test_event.type = "Content Modification Time-REG"
    test_event.evidence = r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00\d\\Control\\DeviceClasses\\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\\[^\\]+\\#"

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches_reg_deviceclass = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches_reg_deviceclass:
        # Extract key values from Evidence
        try:
            match = re.search(r"^\[HKEY_LOCAL_MACHINE\\System\\(ControlSet00\d)\\Control\\DeviceClasses\\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\\[^\\]+?VID_(\w+)&PID_(\w+)#([^\\]+)#", each_low_event.evidence)
            control_set = match.group(1)
            vid = match.group(2)
            pid = match.group(3)
            serial = match.group(4)
        except:
            print(each_low_event.evidence)
        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "USB Device Connected (Winreg DeviceClasses)"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.description = f"USB device connected with Vendor ID '{vid}' and Product ID '{pid}' (Winreg DeviceClasses)."
        high_event.set_keys("ControlSet", control_set)
        high_event.set_keys("VID", vid)
        high_event.set_keys("PID", pid)
        high_event.set_keys("Serial", serial)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"USB device connected with VID '{vid}' and PID '{pid}' in 'HKEY_LOCAL_MACHINE\System\\{control_set}\Control\DeviceClasses\\{{a5dcbf10-6530-11d2-901f-00c04fb951ed}}\\'."
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://doi.org/10.1016/j.diin.2019.02.004'
        # REF For device class id: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-usb-device
        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline