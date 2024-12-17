# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "USB Device Connected (WinEvt)"
analyser_category = "User Activity"


def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Windows USB Device Connected analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindUSBConnectedWinevt(low_timeline, start_id, end_id)


def FindUSBConnectedWinevt(low_timeline, start_id, end_id):
    """Finds Windows USB Device Connected events based on event structure"""

    # Create a test event to match against

    # Windows Event - Windows Partition Diagnostic Event Log
    test_event4 = LowLevelEvent()
    test_event4.type = "Creation Time-EVT"
    test_event4.evidence = r"^\[1006 \/ 0x03ee\] Provider identifier: {.+} Source Name: Microsoft-Windows-Partition"

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches_evt = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event4)

    # Extract details from matching events
    for each_low_event in trigger_matches_evt:
        # Extract key values from Evidence
        match = re.search(r"^\[1006 \/ 0x03ee\] Provider identifier: {.+} Source Name: Microsoft-Windows-Partition Strings: \['\d+'  '.+?'  '.+?'  '\w+'  '\d+'  '\d+'  '\d+'  '(\d+)'  '(\d+)'  '\d+'  '(.+?)'  '(.+?)'  '(.+?)'  '.+?'  '.+?'  '(.+?)'", each_low_event.evidence)
        bytes_per_sector = match.group(1)
        capacity = match.group(2)
        manufacturer = match.group(3)
        model = match.group(4)
        revision = match.group(5)
        parent_id = match.group(6)


        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "USB Device Connected"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.description = f"Possible USB device connected with Manufacter '{manufacturer}', Model '{model}', and revision '{revision}' (Windows Partition Log)."
        high_event.set_keys("BytesPerSector", bytes_per_sector)
        high_event.set_keys("Capacity", capacity)
        high_event.set_keys("Manufacturer", manufacturer)
        high_event.set_keys("Model", model)
        high_event.set_keys("Revision", revision)
        high_event.set_keys("ParentId", parent_id)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Possible USB device connected with Manufacter '{manufacturer}', Model '{model}', and revision '{revision}' (Windows Partition Log). WARNING : If the device is an internal hard drive, this timestamp might be created during boot up."
        reasoning.test_event = test_event4
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://dfir.pubpub.org/pub/h78di10n/release/2'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline