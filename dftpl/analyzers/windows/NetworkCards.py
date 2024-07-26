
import PyDFT.Timelines.HighLevelTimeline
import PyDFT.Events.LowLevelEvent
import PyDFT.Events.HighLevelEvent
import PyDFT.Events.HighLevelReasoningArtefact
import PyDFT.Events.Event
import PyDFT.Utilities.TimeCore
import logging
import PyDFT.Utilities.TimeCore

description = "Network Interfaces"
analyser_category = "System"

def Run(timeline, casepath, queue, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)
    NetworkCards(timeline, queue, start_id, end_id)


def NetworkCards(low_timeline, queue, start_id, end_id):
    """Searches for the installation of network interfaces"""
    high_level_event = PyDFT.Timelines.HighLevelTimeline.high_level_timeline()

    test_event = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event.plugin = "Registry Parser"
    test_event.type = "Last Updated"
    test_event.path = "/Microsoft/Windows NT/CurrentVersion/NetworkCards/[^/]*?$"
    test_event.set_keys("Description", ".*")
    test_event.set_keys("ServiceName", ".*")

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            high_event = PyDFT.Events.HighLevelEvent.high_level_event()
            high_event.add_time(each_event.date_time_min)
            high_event.type = "Network Card Installation"
            high_event.evidence_source = each_event.evidence
            high_event.description = "Network card %s was installed" % each_event.keys["Description"]
            high_event.category = analyser_category
            high_event.device = each_event.evidence
            high_event.keys["Description"] = each_event.keys["Description"]
            high_event.keys["ServiceName"] = each_event.keys["ServiceName"]

            reasoning = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.test_event = test_event
            reasoning.description = "Registry entry %s last updated" % each_event.path
            high_event.trigger = reasoning

            high_level_event.add_event(high_event)

    queue.put(high_level_event)
