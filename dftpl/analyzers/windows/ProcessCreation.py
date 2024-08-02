__author__ = 'Hudan Studiawan'

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Process Creation"
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Process Creation analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindProcessCreation(low_timeline, start_id, end_id)

def FindProcessCreation(low_timeline, start_id, end_id):
    """Finds process creation events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Creation Time-EVT"
    test_event.evidence = r'\[\s*(9707|0x25eb)\s*/\s*(9707|0x25eb)\s*\].*\'([^\']+\.exe)'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        if each_low_event.match(test_event):
            match = re.search(test_event.evidence, each_low_event.evidence)
            if match:
                # Get matched groups from the regex
                windows_event_id = match.group(1)
                windows_event_id_hex = match.group(2)
                executable_name = match.group(3)

                # Create a high level event
                high_event = HighLevelEvent()
                high_event.id = each_low_event.id
                high_event.add_time(each_low_event.date_time_min)
                high_event.evidence_source = each_low_event.evidence
                high_event.type = "Process Creation"
                high_event.description = f"Process creation of '{executable_name}'"
                high_event.category = analyser_category
                high_event.device = each_low_event.plugin
                high_event.files = each_low_event.path
                high_event.set_keys("Windows Event ID", windows_event_id)
                high_event.set_keys("Windows Event ID (hex)", windows_event_id_hex)
                high_event.set_keys("Executable name", executable_name)
                high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

                # Create a reasoning artefact
                reasoning = ReasoningArtefact()
                reasoning.id = each_low_event.id
                reasoning.description = f"Process creation event found in {','.join(each_low_event.provenance['raw_entry'])}"
                reasoning.test_event = test_event

                # Add the reasoning artefact to the high level event
                high_event.trigger = reasoning
                high_timeline.add_event(high_event)

    return high_timeline