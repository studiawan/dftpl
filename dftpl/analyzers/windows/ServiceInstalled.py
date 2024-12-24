# TODO: Missing Authorship
# TODO: Add extra check in case another event source also have the id '7045'?

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Service Installed"
analyser_category = "System"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Service Installed analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindServiceInstalled(low_timeline, start_id, end_id)

def FindServiceInstalled(low_timeline, start_id, end_id):
    """Finds Service Installed events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Content Modification Time-EVT"
    test_event.evidence = r'^\[7045 \/ 0x1b85\]'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:

        # Handling no matches in case another event also uses id 7045
        source_name = ''
        service_name = ''
        image_path = ''
        service_type = ''
        start_type = ''
        account_name = ''

        # Get values from evidence
        match = re.search(r'^\[7045 \/ 0x1b85\] .+? Source Name: (.*?) Strings: \[(?:\'(.*?)\'|None)  (?:\'(.*?)\'|None)  (?:\'(.*?)\'|None)  (?:\'(.*?)\'|None)  (?:\'(.*?)\'|None)\]', each_low_event.evidence)
        if match:
            source_name = match.group(1) or "None"
            service_name = match.group(2) or "None"
            image_path = match.group(3) or "None"
            service_type = match.group(4) or "None"
            start_type = match.group(5) or "None"
            account_name = match.group(6) or "None"

        # Checks event source in case another event source also uses id 7045
        if source_name == "Service Control Manager":
            # Create a high level event
            high_event = HighLevelEvent()
            high_event.id = each_low_event.id
            high_event.add_time(each_low_event.date_time_min)
            high_event.evidence_source = each_low_event.evidence
            high_event.type = "Service Installed"
            high_event.category = analyser_category
            high_event.plugin = each_low_event.plugin
            high_event.files = each_low_event.path
            high_event.description = f"Service installed with name '{service_name}' by account '{account_name}'"
            high_event.set_keys("Service Name", service_name)
            high_event.set_keys("Image Path", image_path)
            high_event.set_keys("Service Type", service_type)
            high_event.set_keys("Start Type", start_type)
            high_event.set_keys("Account Name", account_name)

            high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

            # Create a reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_low_event.id
            reasoning.description = (f"Service installed with path '{image_path}' found by '{source_name}' with event id 7045"
                                     f" in path '{each_low_event.path}'")
            reasoning.test_event = test_event
            reasoning.provenance = each_low_event.provenance
            reasoning.references = 'https://research.splunk.com/endpoint/429141be-8311-11eb-adb6-acde48001122/'

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning.to_dict()

            # Add the high level event to the high level timeline
            high_timeline.add_event(high_event)

    return high_timeline