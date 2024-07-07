__author__ = "Hudan Studiawan"

import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Program Opened"
analyser_category = "System"

def Run(timeline, start_id=0, end_id=None):
    """Runs the ProgramOpened analyser"""
    if end_id == None:
        end_id = len(timeline)
    
    return ProgramOpened(timeline, start_id, end_id)

def ProgramOpened(low_timeline, start_id, end_id):
    """Finds the program opened in the timeline"""

    # Create a high level timeline to store the results
    high_level_timeline = HighLevelTimeline()

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Last Access Time-FILE"

    # Check for NTFS file path and .exe file type
    test_event.evidence = r'NTFS:\\.*\.exe.*Type:\s*file'

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_event in trigger_matches:
        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_event.id
        high_event.add_time(each_event.date_time_min)
        high_event.evidence_source = each_event.evidence
        high_event.type = "Program opened"
        high_event.description = "A Windows program was opened"
        high_event.category = analyser_category
        high_event.device = each_event.plugin
        high_event.files = each_event.path
        high_event.supporting = low_timeline.get_supporting_events(each_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_event.id
        reasoning.description = f"Program {GetFileName(each_event.evidence)} was opened from {each_event.path}"

        # Add the reasoning to the high level event
        high_event.reasoning = reasoning

        # Add the high level event to the timeline
        high_level_timeline.add_event(high_event)

    return high_level_timeline


def GetFileName(path):
    """Returns the file name from the path"""
    pattern = r'NTFS:\\.*\\([^\\]+\.exe).*Type:\s*file'
    match = re.search(pattern, path)
    
    if match:
        return match.group(1)
    else:
        return None