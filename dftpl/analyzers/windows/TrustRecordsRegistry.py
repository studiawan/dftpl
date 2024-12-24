# TODO: Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Microsoft Office Trust Records Registry Key"
analyser_category = "System"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Trust Records Registry Key analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindTrustRecordsRegistry(low_timeline, start_id, end_id)

def FindTrustRecordsRegistry(low_timeline, start_id, end_id):
    """Finds Trust Records Registry Key events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Content Modification Time-REG"
    test_event.evidence = (r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\S*?\\'
                           r'(?:PowerPoint|Excel|Word)\\Security\\Trusted Documents\\TrustRecords\]')

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:

        # Handling no matches
        reg_path = ''
        office_version = ''
        office_app = ''
        entries_string = ''

        # Get values from evidence
        match = re.search(r'^\[(HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\(\S*?)\\(PowerPoint|Excel|Word)\\Security\\Trusted Documents\\TrustRecords)\] (.*)', each_low_event.evidence)
        if match:
            reg_path = match.group(1)
            office_version = match.group(2)
            office_app = match.group(3)
            entries_string = match.group(4) or "None"

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Trust Records Registry Key"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("Key Path", reg_path)
        high_event.set_keys("Office Version", office_version)
        high_event.set_keys("Office Application", office_app)

        entries_len = 0
        # Parse multiple entries
        if entries_string != "None":
            entries_tuple = re.findall(r"(.*?): \[.*?\] \(\d*? bytes\) ?", entries_string)
            entries_len = len(entries_tuple)
            for index, entry in enumerate(entries_tuple):
                high_event.set_keys(f"File{index+1} Path", entry)
        else:
            high_event.set_keys(f"File1 Path", "None")

        high_event.description = f"Update time for '{office_app}' {office_version} trusted documents list with {entries_len} entries"

        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Update time for '{reg_path}' registry key with {entries_len} entries found in '{each_low_event.path}'"
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://www.bleepingcomputer.com/news/security/windows-registry-helps-find-malicious-docs-behind-infections/'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline