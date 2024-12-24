# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Last Time Executed (Program Compatibility Assistant)"
# NOTE : Specifically Windows 11 after 22H2 (https://www.sygnia.co/blog/new-windows-11-pca-artifact/)
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Last Time Executed (Program Compatibility Assistant) analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindLastExecutedPCA(low_timeline, start_id, end_id)

def FindLastExecutedPCA(low_timeline, start_id, end_id):
    """Finds Program Compatibility Assistant events based on event structure"""
    # NOTE : At time of creation, plaso's winpca.py only defines 2 parser (winpca_db0 and winpca_dic)

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Last Time Executed-LOG"
    # Type of parser isn't written in the message
    # Checks for possible description string, then filters by low level event plugin
    test_event.evidence = r'^\[.+\] was executed - '

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        # Ignores events other than PCA
        # TODO: Add exception case handling
        plugin_split = each_low_event.plugin.split('-')

        if plugin_split[1] == "Program Compatibility Assistant (PCA) Log":
            # Create a high level event
            high_event = HighLevelEvent()
            high_event.id = each_low_event.id
            high_event.add_time(each_low_event.date_time_min)
            high_event.evidence_source = each_low_event.evidence
            high_event.type = f"Last Time Executed (PCA plugin '{plugin_split[2]}')"
            high_event.category = analyser_category
            high_event.plugin = each_low_event.plugin
            high_event.files = each_low_event.path

            path = ""
            # 'winpca_db0' event contains more values
            if plugin_split[2] == "winpca_db0":
                # Get values from evidence
                match = re.search(r'^\[(.+)\] was executed -  Description: (.*)'
                                  r' Version: (.*) Vendor: (.*) Exit code: (.*)$', each_low_event.evidence)
                path = match.group(1)
                description = match.group(2)
                version = match.group(3)
                vendor = match.group(4)
                exit_code = match.group(5)
                high_event.set_keys("Path", path)
                high_event.set_keys("Description", description)
                high_event.set_keys("Version", version)
                high_event.set_keys("Vendor", vendor)
                high_event.set_keys("Exit Code", exit_code)
            elif plugin_split[2] == "winpca_dic":
                # Get values from evidence
                match = re.search(r'^\[(.+)\] was executed - $', each_low_event.evidence)
                path = match.group(1)
                high_event.set_keys("Path", path)

            high_event.description = f"Last Time Executed of '{path}'"

            high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

            # Create a reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_low_event.id
            reasoning.description = f"Last Time Executed of '{path}' found in '{each_low_event.path}'"
            reasoning.test_event = test_event
            reasoning.provenance = each_low_event.provenance
            reasoning.references = 'https://artefacts.help/windows_pca.html'

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning.to_dict()

            # Add the high level event to the high level timeline
            high_timeline.add_event(high_event)

    return high_timeline