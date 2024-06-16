__author__ = 'Jony Patterson'

import PyDFT.Timelines.HighLevelTimeline
import PyDFT.Events.LowLevelEvent
import PyDFT.Events.HighLevelEvent
import PyDFT.Events.HighLevelReasoningArtefact
import PyDFT.Events.Event
import PyDFT.Utilities.TimeCore
import logging

description = "Windows Shutdown"
analyser_category = "System"

def Run(timeline, casepath, queue, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)
    LastShutdown(timeline, queue, start_id, end_id)

def LastShutdown(low_timeline, queue, start_id, end_id):
    high_level_timeline = PyDFT.Timelines.HighLevelTimeline.high_level_timeline()

    test_event = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event.type = "Last Updated"
    test_event.path = "/Reliability/shutdown$"

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            high_event = PyDFT.Events.HighLevelEvent.high_level_event()
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "Shutdown time"
            high_event.description = "Windows shut down"
            high_event.category = analyser_category
            high_event.device = each_event.evidence

            reasoning = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Shutdown time found in %s" % each_event.path
            reasoning.test_event = test_event

            high_event.trigger = reasoning

            high_level_timeline.add_event(high_event)

    queue.put(high_level_timeline)

  