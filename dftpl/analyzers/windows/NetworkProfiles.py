import re
import PyDFT.Timelines.HighLevelTimeline
import PyDFT.Events.LowLevelEvent
import PyDFT.Events.HighLevelEvent
import PyDFT.Events.HighLevelReasoningArtefact
import PyDFT.Events.Event
import PyDFT.Utilities.TimeCore
import logging
import PyDFT.Utilities.TimeCore

description = "Network Profiles"
analyser_category = "Network"

def Run(timeline, casepath, queue, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)
    NetworkProfilesWin7(timeline, queue, start_id, end_id)


def NetworkProfilesWin7(low_timeline, queue, start_id, end_id):
    """Searches for times associated with network profiles"""
    high_level_timeline = PyDFT.Timelines.HighLevelTimeline.high_level_timeline()

    test_event = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event.plugin = "Registry Parser"
    test_event.type = "Last Updated"
    test_event.path = "/Microsoft/Windows NT/CurrentVersion/NetworkList/Profiles/{.*?}"

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            created = each_event.keys["DateCreated"]
            created_unix_time = PyDFT.Utilities.TimeCore.Convert128BitWindowsSYSTEMStringToUnixTime(created)
            last_connected = each_event.keys["DateLastConnected"]
            last_connected_unix_time = PyDFT.Utilities.TimeCore.Convert128BitWindowsSYSTEMStringToUnixTime(last_connected)

            # Make event for first connection
            high_event1 = PyDFT.Events.HighLevelEvent.high_level_event()
            high_event1.add_time(created_unix_time)
            high_event1.add_time(last_connected_unix_time)
            high_event1.type = "Network Connection"
            high_event1.evidence_source = each_event.evidence
            high_event1.description = "Network Profile '%s' possibly in use" % each_event.keys["ProfileName"]
            high_event1.category = analyser_category
            high_event1.device = "Device"
            high_event1.keys["Description"] = each_event.keys["Description"]
            high_event1.keys["ProfileName"] = each_event.keys["ProfileName"]
            high_event1.keys["Category"] = each_event.keys["Category"]

            reasoning = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.test_event = test_event
            reasoning.description = "Registry entry %s DateCreated value" % each_event.path
            high_event1.trigger = reasoning
            high_event1.AddSupportingEvidenceArtefact(reasoning)
            high_event1.keys["ProfileGUID"] = re.search("/Microsoft/Windows NT/CurrentVersion/NetworkList/Profiles/({.*?})", each_event.path).group(1)

            #-------------------------------------

            #reasoning = PyDFT.Core.HighLevelEvent.ReasoningArtefact()
            #reasoning.id = each_event.id
            #reasoning.test_event = test_event
            #reasoning.description = "Registry entry %s DateLastConnected value" % each_event.path
            #high_event1.AddSupportingEvidenceArtefact(reasoning)

            # -------------------------------------

            # Make test sub event with Profile GUID
            sub_test_event = PyDFT.Events.LowLevelEvent.low_level_event()
            sub_test_event.keys["ProfileGuid"] = high_event1.keys["ProfileGUID"]

            # Test for this event in a sub timeline
            sub_timeline = low_timeline.get_events_between_datetimes(created_unix_time-60, created_unix_time+60)
            for each_sub_event in sub_timeline:
                if each_sub_event.match(sub_test_event):
                    # If found add as a supporting artefact
                    high_event1.keys["Gateway_MAC"] = each_sub_event.keys["DefaultGatewayMac"]
                    
                    supporting = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
                    supporting.id = each_sub_event.id
                    supporting.test_event = sub_test_event
                    supporting.description = "Profile GUID matched in %s" % each_sub_event.path
                    high_event1.AddSupportingEvidenceArtefact(supporting)

            # Add the events to the timeline
            high_level_timeline.add_event(high_event1)


    queue.put(high_level_timeline)