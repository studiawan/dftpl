__author__ = 'Chris Hargreaves'
__author__ = 'Jony Patterson'

import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.events.LowLevelEvent import LowLevelEvent


description = "Cached Video"
analyser_category = "Web"

def Run(timeline, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)
    
    CachedVideo(timeline, start_id, end_id)

def CachedVideo(low_timeline, start_id, end_id):
    high_level_timeline = HighLevelTimeline()

    test_event = LowLevelEvent()
    test_event.type = "Cached"
    test_event.plugin = "Firefox Cache"
    test_event.keys["Content-Type"] = "video/.*"

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_event in trigger_matches:
        matched_trigger = each_event.match(test_event)
        if matched_trigger:
            high_event = HighLevelEvent()
            high_event.add_time(each_event.date_time_min)
            high_event.type = "Video Cached"
            high_event.evidence_source = each_event.evidence
            high_event.category = analyser_category

            high_event.description = "Video Cached"

            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.test_event = test_event
            reasoning.description = "Content_type of video/webm found in (%s)" % each_event.path
            high_event.trigger = reasoning
            high_event.device = each_event.evidence

            high_event.keys["File Path"] = each_event.path
            high_event.AddFile(each_event.path)

            high_level_timeline.add_event(high_event)
    

