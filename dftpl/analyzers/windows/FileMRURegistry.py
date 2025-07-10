# TODO: Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

# For timestamp conversion
from datetime import datetime,timedelta,timezone

description = "Microsoft Office File MRU Registry Key"
analyser_category = "System"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the File MRU (Most Recently Used) Registry Key analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindFileMRURegistry(low_timeline, start_id, end_id)

def FindFileMRURegistry(low_timeline, start_id, end_id):
    """Finds File MRU (Most Recently Used) Registry Key events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Content Modification Time-REG"
    test_event.evidence = (r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\S*?\\'
                           r'(?:PowerPoint|Excel|Word)\\(?:File MRU|User MRU\\LiveId_.+?\\File MRU)\]')

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
        is_userMRU = False
        entries_string = ''

        # Get values from evidence
        match = re.search(
            r"^\[(HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\(\S*?)\\(PowerPoint|Excel|Word)\\(File MRU|User MRU\\LiveId_.+?\\File MRU))\] (.*)", each_low_event.evidence)
        if match:
            reg_path = match.group(1)
            office_version = match.group(2)
            office_app = match.group(3)
            # Checks if entry is from User MRU (Signed in User)
            if match.group(4) != "File MRU":
                is_userMRU = True
            entries_string = match.group(5) or "None"

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Office File MRU Registry Key"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("Key Path", reg_path)
        high_event.set_keys("Office Version", office_version)
        high_event.set_keys("Office Application", office_app)

        entries_len = 0
        # Parse multiple entries
        # Item number is ordered by ASCII Values
        if entries_string != "None":
            entries_tuple = re.findall(r"(\S*| \d*?): \[.*?\] (.*?)(?=\S*?: |Item|$)", entries_string)
            for index, entries_pair in enumerate(entries_tuple):
                if re.findall(r"(\d+)", entries_pair[0]):
                    entries_len += 1
                    match_items = re.findall(r"\[.*?\]\[T(.*?)\]\[.*?\]\*(.*)", entries_pair[1])
                    high_event.set_keys(f"Item{entries_pair[0]} Name", match_items[0][1].strip())
                    high_event.set_keys(f"Item{entries_pair[0]} Timestamp", Integer8DateTimeConverter(match_items[0][0]))
                else:
                    high_event.set_keys(f"{entries_pair[0]}", entries_pair[1].strip())


        else:
            high_event.set_keys(f"Entry", "None")
        if is_userMRU:
            high_event.description = f"Update time for most recently used documents for logged in microsoft user of '{office_app}' {office_version} with {entries_len} entries"
        else:
            high_event.description = f"Update time for most recently used documents for user of '{office_app}' {office_version} with {entries_len} entries"

        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Update time for '{reg_path}' registry key with {entries_len} entries found in '{each_low_event.path}'"
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://www.cybertriage.com/artifact/office-mru-registry/'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline

def Integer8DateTimeConverter(int8_in):
    """
    Converts Integer8 Windows Timestamp format from hex to iso formatted string
    REF : https://stackoverflow.com/questions/4869769/convert-64-bit-windows-date-time-in-python
    """
    try:
        ms = int(int8_in, 16) / 10
    except ValueError:
        return "ERROR: Timestamp conversion error"
    return (datetime(1601, 1, 1,tzinfo=timezone.utc) + timedelta(microseconds=ms)).isoformat()