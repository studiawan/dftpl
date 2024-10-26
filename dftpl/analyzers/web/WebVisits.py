__author__ = 'Chris Hargreaves'

import re
from datetime import datetime, timedelta
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Web Visit"
analyser_category = "Web Overview"

def Run(timeline: LowLevelTimeline, start_id: int=0, end_id=None) -> HighLevelTimeline:
    """Finds Web Visits"""
    if end_id == None:
        end_id = len(timeline.events)

    return FindWebVisits(timeline, start_id, end_id)


def FindWebVisits(low_timeline: LowLevelTimeline, start_id: int, end_id: int) -> HighLevelTimeline:
    """Finds Web Visits"""

    # Create test event that matches any URL in any browser
    test_event = LowLevelEvent()
    test_event.type = "WEBHIST"
    test_event.evidence = r"\b(http|https|www)\b"

    # Create a new high level timeline
    high_timeline = HighLevelTimeline()

    # Find all events that match the test event
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            # Create a new high level event with some data
            high_event = HighLevelEvent()
            high_event.id = each_event.id
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "Web Visit"
            
            # Extract the domain from the URL
            domain = ExtractDomainFromURL(each_event.evidence)
            high_event.description = "Web Visit to '%s'" % domain
            high_event.category = analyser_category
            high_event.plugin = each_event.plugin
            high_event.files = each_event.path
            high_event.set_keys("Browser", GetBrowser(each_event.plugin))
            high_event.set_keys("URL", ExtractURL(each_event.evidence))
            high_event.set_keys("Domain", domain)
            high_event.supporting = low_timeline.get_supporting_events(each_event.id)

            # Construct a reasoning artefact and add it to the high level event
            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "URL found in " + each_event.evidence
            reasoning.test_event = test_event
            reasoning.provenance = each_event.provenance

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning.to_dict()

            # Add the high level event to the high level timeline
            high_timeline.add_event(high_event)
            
    return high_timeline


def GetBrowser(browser_string):
    """Extracts Browser from Plugin Name"""
    browser_data = browser_string.split(" ")[0]
    return browser_data

def ExtractDomainFromURL(url):

    # Regular expression to match the desired part of the URL
    pattern = r"https?://([a-zA-Z0-9.-]+)"

    # Using re.search to find the match
    match = re.search(pattern, url)

    # Extracting and printing the matched string
    if match:
        return match.group(1)
    else:
        return None


def ExtractPathFromLocalURL(url):
    short_url = re.sub("file://", "", url)
    return short_url    

def ExtractURL(text):
    pattern = r"https?://[^\s,]+"
    match = re.search(pattern, text)

    if match:
        url = match.group(0)
        return url
    else:
        return None
