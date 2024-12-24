# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Last Time Executed (Prefetch)"
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Last Time Executed (Prefetch) analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindLastExecutedPrefetch(low_timeline, start_id, end_id)

def FindLastExecutedPrefetch(low_timeline, start_id, end_id):
    """Finds prefetch events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = r"^(?:Previous )?Last Time Executed-LOG$"
    test_event.evidence = r'^Prefetch \[.+\] was executed'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        # Get values from evidence
        match = re.search(r'^Prefetch \[(.+)\] was executed - run count (\d+)'
                          r' path hints: (.+) hash: (\S+) (.+)$', each_low_event.evidence)
        app_name = match.group(1)
        run_count = match.group(2)
        # Paths after the 1st doesn't have a starting "\"
        app_path_list = match.group(3).split("; \\")
        file_hash = match.group(4)
        # Returns 1 list or a tuple of lists containing each volume's information
        volume_tuple = re.findall(r'volume: (\d+) \[serial number: (\S+)  device path: (.+?)\]+', match.group(5))

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        # Either "Previous Last Time Executed" or "Last Time Executed"
        high_event.type = f"{each_low_event.type.split('-')[0]} (Prefetch)"
        high_event.description = f"{each_low_event.type.split('-')[0]} of '{app_name}' (hash: {file_hash})"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("App Name", app_name)
        high_event.set_keys("Run Count", run_count)
        high_event.set_keys("File Hash", file_hash)
        # Set keys for values with variable amount
        for index, path in enumerate(app_path_list):
            if index > 0:
                high_event.set_keys(f"App Path {index + 1}", f"\\{path}")
            else:
                high_event.set_keys(f"App Path {index+1}", path)
        for volume_list in volume_tuple:
            high_event.set_keys(f"Volume {volume_list[0]} Serial Num", volume_list[1])
            high_event.set_keys(f"Volume {volume_list[0]} Device Path", volume_list[2])
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"{each_low_event.type.split('-')[0]} of '{app_name}' (hash: {file_hash}) found in prefetch file '{each_low_event.path}'"
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline