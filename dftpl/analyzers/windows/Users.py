
import PyDFT.Timelines.HighLevelTimeline
import PyDFT.Events.LowLevelEvent
import PyDFT.Events.HighLevelEvent
import PyDFT.Events.HighLevelReasoningArtefact
import PyDFT.Events.Event
import PyDFT.Utilities.TimeCore
import logging
import os

description = "Creation of User"
analyser_category = "System"


def Run(timeline, casepath, queue, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)
    CreatedUser(timeline, queue, start_id, end_id)

def CreatedUser(low_timeline, queue, start_id, end_id):
    high_level_timeline = PyDFT.Timelines.HighLevelTimeline.high_level_timeline()

    # Test event for entry in SAM for a user
    test_event = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event.plugin = "Registry Parser"
    test_event.type = "Last Updated"
    test_event.path = "/SAM/Domains/Account/Users/Names/.+$"
    # XP - /SAM/SAM/Domains/Acounts/USers/Names/Username in Reg
    # 7 - /CMI-CreativeHive{GUID}/SAM/Doains/Account/Users/Names/Username in Reg

    # Test event for creation of folder in /Users
    test_event2 = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event2.plugin = "Mounted File System|MFT"
    test_event2.type = "Created"
    test_event2.path = "/Users/.[^/]+$"

    test_dict = {}
    test_dict["SAM"] = test_event
    test_dict["Users folder"] = test_event2


    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_dict)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            high_event = PyDFT.Events.HighLevelEvent.high_level_event()
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "User created"
            high_event.keys["Username"] = os.path.split(each_event.path)[1]
            high_event.description = "User '%s' created" % high_event.keys["Username"]
            high_event.category = analyser_category
            high_event.device = each_event.evidence

            reasoning = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Last Write for SAM Registry entry " + each_event.path + " in " + each_event.event_provenance.source
            reasoning.test_event = test_event
            high_event.trigger = reasoning

            folder_creation_results = SearchForFolderCreation(each_event, low_timeline, high_event.keys["Username"])
            if folder_creation_results[0]:
                matched_event = low_timeline[folder_creation_results[1].id]
                high_event.add_time(matched_event.date_time_min)
                high_event.add_time(matched_event.date_time_max)
                high_event.AddSupportingEvidenceArtefact(folder_creation_results[1])
            else:
                high_event.AddContradictoryEvidenceArtefact(folder_creation_results[1])

            high_level_timeline.add_event(high_event)

    queue.put(high_level_timeline)



def SearchForFolderCreation(low_event, low_timeline, username):
    start_date = low_event.date_time_min - (60*5) # minus 5 mins
    end_date = low_event.date_time_max + (60*5) # plus 5 mins

    # Test event checks if
    test_event2 = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event2.plugin = "Mounted File System|MFT"
    test_event2.type = "Created"
    test_event2.path = "/Users/" + username

    mini_timeline = low_timeline.get_events_between_datetimes(start_date, end_date)
    for each_event in mini_timeline:
        if each_event.match(test_event2):
            reasoning = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Folder %s Created" % each_event.path
            reasoning.test_event = test_event2
            return (True, reasoning)


    reasoning = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
    reasoning.id = -1
    reasoning.description = "Creation of user folder for %s not found at same time" % username
    reasoning.test_event = test_event2

    return (False, reasoning)