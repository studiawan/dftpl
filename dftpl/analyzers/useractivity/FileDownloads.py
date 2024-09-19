__author__ = 'Chris Hargreaves, Hudan Studiawan'

import re
import urllib.parse
from datetime import datetime, timedelta
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "File Downloaded"
analyser_category = "User Activity"

def Run(timeline: LowLevelTimeline, start_id: int=0, end_id=None) -> HighLevelTimeline:
    """Runs the File Downloaded analyser"""
    if end_id == None:
        end_id = len(timeline.events)

    return FileDownloaded(timeline, start_id, end_id)

def FileDownloaded(low_timeline: LowLevelTimeline, start_id: int, end_id: int) -> HighLevelTimeline:
    """Finds file downloads based on file path"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Creation Time-FILE"
    test_event.evidence = r'\\Users\\[^\\]+\\Downloads'

    # Create a high level timeline to store the results
    high_level_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_event in trigger_matches:
        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_event.id
        high_event.add_time(each_event.date_time_min)
        high_event.evidence_source = each_event.evidence
        high_event.type = "File Downloaded"
        file_name = re.search(r'\\Downloads\\([^\\]+\.[^\\\s]+)', each_event.evidence).group(1)
        user = re.search(r'\\Users\\([^\\]+)\\Downloads', each_event.evidence).group(1)
        
        high_event.description = "File Downloaded (%s)" % file_name
        high_event.category = analyser_category
        high_event.device = each_event.plugin
        high_event.files = each_event.path
        high_event.set_keys("File Name", file_name )
        high_event.set_keys("User", user)
        high_event.supporting = low_timeline.get_supporting_events(each_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_event.id
        reasoning.description = f"Created file in downloads folder: {file_name}"
        reasoning.test_event = test_event
        reasoning.provenance = each_event.provenance

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()
        
        # pattern for test event
        url_pattern = r"https?:\/\/[^\s]+\/"

        # Define the second regex pattern (could be user input or another variable)
        encoded_string = urllib.parse.quote(file_name)
        file_pattern = re.escape(encoded_string)

        # Combine the two patterns to ensure the match includes the file name
        combined_pattern = fr"{url_pattern}{file_pattern}"

        # Test event for source URL
        source_url_test_event = LowLevelEvent()
        source_url_test_event.type = "Start Time-WEBHIST"
        source_url_test_event.evidence = combined_pattern

        # Find matching events to find source URL
        fuzzy_period = timedelta(seconds=180)
        start_time = datetime.fromisoformat(each_event.date_time_min) - fuzzy_period
        end_time = datetime.fromisoformat(each_event.date_time_min) + fuzzy_period

        # Find source URL
        results = low_timeline.get_list_of_matches_in_sub_timeline(source_url_test_event, start_time=start_time, end_time=end_time)

        if results:
            supporting = {}
            for index, result in enumerate(results):
                # Create a reasoning artefact for source URL
                supporting[f"source-{index}"] = {
                    'id_source': result.id,
                    'description_source': "File Downloaded ({}) from {}".format(file_name, GetURIStringFromMessage(result.evidence)),
                    'test_event_source': {
                        'type': source_url_test_event.type,
                        'evidence': source_url_test_event.evidence
                    },
                    'provenance_source': result.provenance
                }

            # Add the supporting events to the high level event
            high_event.trigger.update(supporting) 

        # Add the high level event to the high level timeline
        high_level_timeline.add_event(high_event)
    
    return high_level_timeline


def GetURIStringFromMessage(message: str) -> str:
    """Extracts the URI from a message"""
    uri = re.search(r"https?:\/\/[^\s]+\/", message)
    if uri:
        return uri.group(0)
    else:
        return None