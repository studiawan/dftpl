# TODO: Missing Authorship

import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Deletion Time (Recycle Bin)"
analyser_category = "System"

def Run(timeline: LowLevelTimeline, start_id: int=0, end_id=None) -> HighLevelTimeline:
    """Runs the Recycle Bin analyser"""
    if end_id == None:
        end_id = len(timeline.events)
    
    return FindRecycleBin(timeline, start_id, end_id)

def FindRecycleBin(low_timeline: LowLevelTimeline, start_id: int, end_id: int) -> HighLevelTimeline:
    """Finds Recycle Bin events based on event structure"""

    # Create a high level timeline to store the results
    high_level_timeline = HighLevelTimeline()

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Content Deletion Time-RECBIN"
    # Message only consists of deleted file's original path
    test_event.evidence = r".*"

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    # Extract details from matching events
    for each_event in trigger_matches:


        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_event.id
        high_event.add_time(each_event.date_time_min)
        high_event.evidence_source = each_event.evidence
        high_event.type = "Deletion Time (Recycle Bin)"
        high_event.description = f"Found deletion time for '{each_event.evidence}'"
        high_event.category = analyser_category
        high_event.plugin = each_event.plugin
        high_event.files = each_event.path
        high_event.supporting = low_timeline.get_supporting_events(each_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_event.id
        reasoning.description = "Deletion time found in '%s'" % each_event.path
        reasoning.test_event = test_event
        reasoning.provenance = each_event.provenance
        reasoning.references = "https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/"

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_level_timeline.add_event(high_event)

    return high_level_timeline
