# TODO: Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Run/Run Once Registry Key"
analyser_category = "System"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Run/Run Once Registry Key analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindRunRunOnceRegistry(low_timeline, start_id, end_id)

def FindRunRunOnceRegistry(low_timeline, start_id, end_id):
    """Finds Run/Run Once Registry Key events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Content Modification Time-REG"
    test_event.evidence = (r'^\[(?:HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software\\(?:WOW6432Node\\)?'
                           r'Microsoft\\Windows\\CurrentVersion\\'
                           r'(?:Run|RunOnce|RunOnce\\Setup|RunServices|RunServicesOnce)\]')

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:

        # Handling no matches
        reg_path = ''
        entries_string = ''

        # Get values from evidence
        match = re.search(r'^\[((?:HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software'
                          r'\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\'
                          r'(?:Run|RunOnce|RunOnce\\Setup|RunServices|RunServicesOnce))\]'
                          r' Entries: \[(.*)\]', each_low_event.evidence)
        if match:
            reg_path = match.group(1)
            entries_string = match.group(2) or "None"


        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Run/Run Once Registry Key"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("Key Path", reg_path)

        entries_len = 0
        # Parse multiple entries
        if entries_string != "None":
            entries_tuple = re.findall(r"\'(.*?): (.*?)\'", entries_string)
            entries_len = len(entries_tuple)
            for index, entries_pair in enumerate(entries_tuple):
                high_event.set_keys(f"Program{index+1} Name", entries_pair[0])
                high_event.set_keys(f"Program{index+1} Path", entries_pair[1])
        else:
            high_event.set_keys(f"Program1 Name", "None")
            high_event.set_keys(f"Program1 Path", "None")

        high_event.description = f"Update time for list of programs run when user logon at '{reg_path}' registry key with {entries_len} entries"

        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Update time for '{reg_path}' registry key with {entries_len} entries found in '{each_low_event.path}'"
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://attack.mitre.org/techniques/T1547/001/'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline