__author__ = 'Chris Hargreaves'

import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Software Installed"
analyser_category = "System"

def Run(timeline, start_id=0, end_id=None, type="generic"):
    if end_id == None:
        end_id = len(timeline)

    if type == "firefox":
        return FindFirefoxInstallation(timeline, start_id, end_id)
    
    elif type == "generic":
        return GenericInstallation(timeline, start_id, end_id)

def GenericInstallation(low_timeline, start_id, end_id):
    high_timeline = HighLevelTimeline()

    uninstall_reg_key = LowLevelEvent()
    uninstall_reg_key.path = ".*Software/Microsoft/Windows/CurrentVersion/Uninstall/(.*)"
    uninstall_reg_key.plugin = "Registry"

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, uninstall_reg_key)

    for each_event in trigger_matches:
        if each_event.match(uninstall_reg_key):
            high_event = HighLevelEvent()
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence

            application_name = re.search(".*Software/Microsoft/Windows/CurrentVersion/Uninstall/(.*)", each_event.path).group(1)

            high_event.description = "Application installed ({})".format(application_name)
            high_event.type = "Application installed"
            high_event.category = analyser_category
            high_event.device = each_event.evidence

            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Uninstall registry key update time"
            reasoning.test_event = uninstall_reg_key

            high_event.trigger = reasoning

            high_timeline.add_event(high_event)


def FindFirefoxInstallation(low_timeline, start_id, end_id):
    high_timeline = HighLevelTimeline()

    firefox_folder_test_event = LowLevelEvent()
    firefox_folder_test_event.type = "Created"
    firefox_folder_test_event.path = "/Program Files/Mozilla Firefox$"
    firefox_folder_test_event.plugin = "Mounted File System"

    firefox_program_test_event = LowLevelEvent()
    firefox_program_test_event.type = "Created"
    firefox_program_test_event.path = ".*?/firefox.exe"
    firefox_program_test_event.plugin = "Mounted File System"

    list_of_match_events = {"firefox_folder_creation": firefox_folder_test_event,
                            "firefox_program_creation": firefox_program_test_event}

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, list_of_match_events)

    for each_event in trigger_matches:
        first_match_id = each_event.match_any_test_event(list_of_match_events)
        if first_match_id:
            results = low_timeline.get_list_of_matches_in_sub_timeline(list_of_match_events,
                         start=each_event.date_time_min-60*1, end=each_event.date_time_min+60*1)
            high_event = HighLevelEvent()
            high_event.category = analyser_category
            high_event.type = "Program Installed"
            high_event.description = "Firefox Installed"
            high_event.device = each_event.evidence
            high_event.evidence_source = each_event.evidence

            trigger = ReasoningArtefact()
            trigger.description = "%s (%s)" % (first_match_id, results[first_match_id].path)
            trigger.id = results[0][0].id
            trigger.test_event = list_of_match_events[first_match_id]
            high_event.trigger = trigger

            # For each time in each event update the high level one
            for each_match in results:
                high_event.add_time(results[0][0].date_time_min)
                high_event.add_time(results[0][0].date_time_max)

            # For each artefact found add to supporting
            for each_match in results:
                supporting = ReasoningArtefact()
                supporting.description = "%s (%s)" % (each_match, results[each_match].path)
                supporting.id = each_match[0].id
                supporting.test_event = list_of_match_events[each_match[1]]
                high_event.AddSupportingEvidenceArtefact(supporting)

            high_timeline.add_event(high_event)
