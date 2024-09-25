__author__ = 'Hudan Studiawan'

import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.events.LowLevelEvent import LowLevelEvent


description = "Cached Images"
analyzer_category = "Web"

def Run(timeline, start_id=0, end_id=None):
    """Run the analyzer"""
    if end_id == None:
        end_id = len(timeline.events)
    
    CachedImages(timeline, start_id, end_id)

def CachedImages(low_timeline, start_id, end_id):
    """Find all images cached in the timeline"""

    # Create a high level timeline to store the results
    high_level_timeline = HighLevelTimeline()

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "WEBHIST"
    test_event.evidence = r'https.*Content-Type:\s*image/'

    # Find all events that match the test event
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    for each_event in trigger_matches:
        # Create a high level event to store the results
        high_event = HighLevelEvent()
        high_event.id = each_event.id
        high_event.add_time(each_event.date_time_min)

        # Extract the URL, filename, and content type from the message
        url, filename, content_type = GetURIAndFilename(each_event.evidence)

        high_event.type = "Image Cached"
        high_event.evidence_source = each_event.evidence
        high_event.category = analyzer_category
        high_event.description = f"Image cached: {filename}"
        high_event.keys["File Path"] = each_event.path
        high_event.keys["Content-Type"] = content_type
        high_event.keys["URL"] = url
        high_event.keys["Filename"] = filename
        high_event.plugin = each_event.plugin
        high_event.supporting = low_timeline.get_supporting_events(each_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_event.id
        reasoning.test_event = test_event
        reasoning.description = f"Content_type of {content_type} found in {each_event.path}"  

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning
        
        # Add the high level event to the high level timeline
        high_level_timeline.add_event(high_event)
    
    return high_level_timeline


def GetURIAndFilename(log_entry):
    """Extract URI, filename, and content type from the log entry"""
    pattern = re.compile(
        r'URL: (?P<uri>https://[^\s]+/(?P<filename>[^/\s]+\.png)).*?Content-Type: (?P<content_type>image/[^\s;]+)',
        re.DOTALL
    )

    match = pattern.search(log_entry)

    if match:
        url = match.group('uri')
        filename = match.group('filename')
        content_type = match.group('content_type')
        
        return url, filename, content_type
    else:
        return None, None, None