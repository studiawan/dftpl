__author__ = 'Chris Hargreaves'

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Web Visit"
analyser_category = "Web Overview"

def Run(timeline, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)

    return FindWebVisits(timeline, start_id, end_id)


def FindWebVisits(low_timeline, start_id, end_id):
    """Finds Web Visits"""

    # Create test event that matches any URL in any browser
    test_event = LowLevelEvent()
    test_event.type = "URL Visit"

    # Create a new high level timeline
    high_timeline = HighLevelTimeline()

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            # Create a new high level event with some data
            high_event = HighLevelEvent()
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "Web Visit"
            
            if each_event.path[0:4] == "file":
                #domain = ExtractPathFromLocalURL(each_event.path)
                #high_event.description = "Local Visit to '%s'" % domain
                # IGNORE LOCAL EVENT AS WILL BE PICKED UP IN LOCAL FILE ACCESS
                continue
            else:
                domain = ExtractDomainFromURL(each_event.path)
                high_event.description = "Web Visit to '%s'" % domain
            
            high_event.category = analyser_category
            high_event.device = each_event.evidence
            high_event.set_keys("Browser", GetBrowser(each_event.plugin))
            high_event.set_keys("URL(%s)" % str(high_event.date_time_min), each_event.path)
            high_event.set_keys("Domain", domain)

            # Construct a reasoning artefact and add it to the high level event
            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "URL found in " + each_event.event_provenance.source
            reasoning.test_event = test_event
            high_event.trigger = reasoning

            # check if there is any cached content with that domain at a similar time
            cache_test_event = LowLevelEvent()
            cache_test_event.plugin = "Firefox Cache"
            cache_test_event.type = "Cached"
            cache_test_event.keys["url"] = "HTTP:" + "http://" +  high_event.keys["Domain"] # should update cache parser so this HTTP: is not necessary

            results = low_timeline.get_events_between_datetimes(each_event.date_time_min-60, each_event.date_time_min+60)
            for each_sub_event in results:
                if each_sub_event.match(cache_test_event):
                    cache_reasoning = ReasoningArtefact()
                    cache_reasoning.id = each_sub_event.id
                    cache_reasoning.description = "Cache entry found in " + each_sub_event.event_provenance.source
                    cache_reasoning.test_event = cache_test_event
                    high_event.AddSupportingEvidenceArtefact(cache_reasoning)
                    high_event.AddFile(each_sub_event.path)

            if len(results) == 0:
                cache_reasoning = ReasoningArtefact()
                cache_reasoning.id = -1
                cache_reasoning.description = "No cache entries found for " + cache_test_event.keys["url"]
                cache_reasoning.test_event = cache_test_event
                high_event.AddContradictoryEvidenceArtefact(cache_reasoning)

            # Rather than adding the event, check if it is the same as another event within a certain period
            # If so, merge them rather than adding a new separate event
            fuzzy_period = 600 # 10 minutes
            indexes = high_timeline.get_indexes_of_events_between_datetimes(high_event.date_time_min-fuzzy_period, high_event.date_time_max+fuzzy_period)
            merged = False
            for each_index in indexes:
                if high_timeline.timeline[each_index].IntersectsWith(high_event, min_increment=fuzzy_period, max_increment=fuzzy_period):
                    # don't add it, merge it with existing
                    high_timeline.timeline[each_index].merge(high_event)
                    merged = True

            # if the event didn't get merged with anything existing, add it as normal
            if merged == False:
                high_timeline.add_event(high_event)


def GetBrowser(browser_string):
    """Extracts Browser from Plugin Name"""
    browser_data = browser_string.split(" ")[0]
    return browser_data

def ExtractDomainFromURL(url):

    short_url = re.sub("https?://", "", url)
    short_url = re.sub(":Host: ", "", short_url) # present in some Internet Explorer records
    pos = short_url.find("/")

    if pos == -1:
        return short_url
    else:
        return short_url[0:pos]

def ExtractPathFromLocalURL(url):
    short_url = re.sub("file://", "", url)
    return short_url
    
#print(ExtractDomainFromURL("http://www.google.co.uk"))



