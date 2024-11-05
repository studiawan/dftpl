# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Device Installation"
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Process Creation analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindDeviceInstallation(low_timeline, start_id, end_id)

def FindDeviceInstallation(low_timeline, start_id, end_id):
    """Finds process creation events based on event structure"""

    # Create a test event to match against
    test_event1 = LowLevelEvent()
    test_event1.type = "Added Time-LOG"
    test_event1.evidence = r'Device Install \(.+\) - .+ -'

    test_event2 = LowLevelEvent()
    test_event2.type = "End Time-LOG"
    test_event2.evidence = r'Device Install \(.+\) - .+ -'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches_start = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event1)
    trigger_matches_end = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event2)

    # Extract details from matching events
    for each_low_event in trigger_matches_start:

        # Extract key values from Evidence
        match = re.search(r'^Device Install \((.+)\) - (.+) - (.+)$', each_low_event.evidence)
        title_description = match.group(1)
        instance_id = match.group(2)
        status_value = match.group(3)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Device Installation"
        high_event.description = f"Start of installation with device instance ID '{instance_id}'"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("Title Description", title_description)
        high_event.set_keys("Device Instance ID", instance_id)
        high_event.set_keys("Status Value", status_value)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Start of installation with device instance ID '{instance_id}'"
        reasoning.test_event = test_event1
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/format-of-a-text-log-section'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    for each_low_event in trigger_matches_end:
        # Extract key values from Evidence
        match = re.search(r'^Device Install \((.+)\) - (.+) - (.+)$', each_low_event.evidence)
        title_description = match.group(1)
        instance_id = match.group(2)
        status_value = match.group(3)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Device Installation"
        high_event.description = f"End of installation with device instance ID '{instance_id}'"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("Title Description", title_description)
        high_event.set_keys("Device Instance ID", instance_id)
        high_event.set_keys("Status Value", status_value)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"End of installation with device instance ID '{instance_id}'"
        reasoning.test_event = test_event2
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/format-of-a-text-log-section'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)


    return high_timeline