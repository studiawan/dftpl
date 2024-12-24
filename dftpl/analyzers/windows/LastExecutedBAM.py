# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Last Time Executed (Registry BAM)"
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Last Time Executed (Registry Background Activity Moderator) analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindLastExecutedBAM(low_timeline, start_id, end_id)

def FindLastExecutedBAM(low_timeline, start_id, end_id):
    """Finds Background Activity Moderator registry events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Last Time Executed-REG"
    # 1. Path can include string not starting with "\" such as "windows.immersivecontrolpanel_cw5n1h2txyewy"
    # 2. Type of parser isn't written in the message
    # Checks for possible user id string, then filters by low level event plugin
    test_event.evidence = r'\[\S+\]$'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        # TODO: Add exception case handling
        # Ignores events other than BAM
        if each_low_event.plugin == "REG-Background Activity Moderator Registry Key-winreg/bam":
            # Get values from evidence
            match = re.search(r'^(.+) \[(\S+)\]$', each_low_event.evidence)
            path = match.group(1)
            user_id = match.group(2)
            # Get file name for description
            file_name = re.findall(r"\\?([^\\]+)$", path)[0]

            # Create a high level event
            high_event = HighLevelEvent()
            high_event.id = each_low_event.id
            high_event.add_time(each_low_event.date_time_min)
            high_event.evidence_source = each_low_event.evidence
            # Either "Previous Last Time Executed" or "Last Time Executed"
            high_event.type = "Last Time Executed (Registry BAM)"
            high_event.description = f"Last Time Executed of '{file_name}' by user id '{user_id}'"
            high_event.category = analyser_category
            high_event.plugin = each_low_event.plugin
            high_event.files = each_low_event.path
            high_event.set_keys("Path", path)
            high_event.set_keys("User ID", user_id)

            high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

            # Create a reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_low_event.id
            reasoning.description = f"Last Time Executed of '{path}' found in '{each_low_event.path}' by Background Activity Monitor"
            reasoning.test_event = test_event
            reasoning.provenance = each_low_event.provenance
            reasoning.references = 'https://docs.velociraptor.app/docs/forensic/evidence_of_execution/'

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning.to_dict()

            # Add the high level event to the high level timeline
            high_timeline.add_event(high_event)

    return high_timeline