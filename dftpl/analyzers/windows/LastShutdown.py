__author__ = 'Jony Patterson'

import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Windows Shutdown"
analyser_category = "System"

def Run(timeline: LowLevelTimeline, start_id: int=0, end_id=None) -> HighLevelTimeline:
    """Runs the LastShutdown analyser"""
    if end_id == None:
        end_id = len(timeline.events)
    
    return LastShutdown(timeline, start_id, end_id)

def LastShutdown(low_timeline: LowLevelTimeline, start_id: int, end_id: int) -> HighLevelTimeline:
    """Finds the last shutdown time in the timeline"""

    # Create a high level timeline to store the results
    high_level_timeline = HighLevelTimeline()

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Creation Time-EVT"

    # Windows Event ID 1074 is the event ID for system shutdown in Windows 11
    test_event.evidence = r"\b(1074)\b.*?\b(0x0432)\b"

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    # Extract details from matching events
    for each_event in trigger_matches:
        match = re.search(test_event.evidence, each_event.evidence)
        if match:
            # Get matched groups from the regex
            windows_event_id = match.group(1)
            windows_event_id_hex = match.group(2)

            # Create a high level event
            high_event = HighLevelEvent()
            high_event.id = each_event.id
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "Shutdown time"
            high_event.description = "Windows shut down"
            high_event.category = analyser_category
            high_event.plugin = each_event.plugin
            high_event.files = each_event.path
            high_event.set_keys("Windows Event ID", windows_event_id)
            high_event.set_keys("Windows Event ID (hex)", windows_event_id_hex)
            high_event.supporting = low_timeline.get_supporting_events(each_event.id)

            # Create a reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Shutdown time found in %s" % each_event.path
            reasoning.test_event = test_event
            reasoning.provenance = each_event.provenance
            reasoning.references = "https://shellgeek.com/event-id-1074-system-restart-or-shutdown/"

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning.to_dict()

            # Add the high level event to the high level timeline
            high_level_timeline.add_event(high_event)
    
    return high_level_timeline
