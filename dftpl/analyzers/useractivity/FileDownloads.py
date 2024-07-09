__author__ = 'Chris Hargreaves, Hudan Studiawan'

import re
import urllib.parse
from datetime import datetime, timedelta
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "File Downloaded"
analyser_category = "User Activity"

def Run(timeline, start_id=0, end_id=None):
    """Runs the File Downloaded analyser"""
    if end_id == None:
        end_id = len(timeline)

    return FileDownloaded(timeline, start_id, end_id)

def FileDownloaded(low_timeline, start_id, end_id):
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
        if each_event.match(test_event):
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

            # Create a reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = f"Created time for file in downloads folder {','.join(each_event.provenance['raw_entry'])}"
            reasoning.test_event = test_event

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning
            
            # pattern for test event
            url_pattern = r"https?:\/\/[^\s]+\/"

            # Define the second regex pattern (could be user input or another variable)
            encoded_string = urllib.parse.quote(file_name)
            file_pattern = re.escape(encoded_string)

            # Combine the two patterns to ensure the match includes the file name
            combined_pattern = fr"{url_pattern}{file_pattern}"

            # Test event for source URL
            source_url_test_event = LowLevelEvent()
            source_url_test_event.type = "End Time-WEBHIST"
            source_url_test_event.evidence = combined_pattern

            # Find matching events to find source URL
            fuzzy_period = timedelta(seconds=180)
            start_time = datetime.fromisoformat(each_event.date_time_min) - fuzzy_period
            end_time = datetime.fromisoformat(each_event.date_time_min) + fuzzy_period

            # Find source URL
            results = low_timeline.get_list_of_matches_in_sub_timeline(source_url_test_event, start=start_time, end=end_time)

            if results:
                supporting = []
                for result in results:
                    # Create a reasoning artefact for source URL
                    supporting_event = ReasoningArtefact()
                    supporting_event.id = result.id
                    supporting_event.description = "File Downloaded ({}) from {}".format(file_name, GetURIStringFromMessage(result.evidence))
                    supporting_event.date_time_min = result.date_time_min
                    supporting_event.test_event = source_url_test_event
                    supporting.append(supporting_event)

                high_event.supporting = supporting

            high_level_timeline.add_event(high_event)
    
    return high_level_timeline


def GetURIStringFromMessage(message):
    """Extracts the URI from a message"""
    uri = re.search(r"https?:\/\/[^\s]+\/", message)
    if uri:
        return uri.group(0)
    else:
        return None