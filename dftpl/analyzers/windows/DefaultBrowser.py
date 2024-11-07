# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

description = "Default Browser"
analyser_category = "Windows"


def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Default Browser analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)

    return FindDefaultBrowser(low_timeline, start_id, end_id)


def FindDefaultBrowser(low_timeline, start_id, end_id):
    """Finds default drowser based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Content Modification Time-REG"
    test_event.evidence = r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        # Get matched groups from the regex
        match = re.search(r'\] Hash: \[.+\] (.+) ProgId: \[.+\] (.+)$', each_low_event.evidence)
        key_hash = match.group(1)
        key_prog_id = match.group(2)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        high_event.type = "Default Browser"
        high_event.description = f"Default browser's ProgId is '{key_prog_id}'"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("Hash", key_hash)
        high_event.set_keys("ProgId", key_prog_id)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Default browser's ProgId found in registry 'HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\\UrlAssociations\https\\UserChoice' with value '{key_prog_id}'"
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://forensafe.com/blogs/Windows-Default-Browser.html'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline