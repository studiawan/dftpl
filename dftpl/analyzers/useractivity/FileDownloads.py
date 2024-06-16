__author__ = 'Chris Hargreaves'

import re
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
    test_event.type = "Created|c_time"
    test_event.path = ".*/Users/(.*)/Downloads/(.*)"

    # Create a high level timeline to store the results
    high_level_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    # Extract details from matching events
    for each_event in trigger_matches:
        if each_event.match(test_event):
            # Create a high level event
            high_event = HighLevelEvent()
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "File Downloaded"
            file_name = re.search(".*/Users/(.*)/Downloads/(.*)", each_event.path).group(2)
            user = re.search(".*/Users/(.*)/Downloads/(.*)", each_event.path).group(1)
            high_event.AddFile(each_event.path)
            high_event.set_keys("File Name", file_name )
            high_event.set_keys("User", user)
            high_event.description = "File Downloaded (%s)" % file_name
            high_event.category = analyser_category
            high_event.device = each_event.evidence

            # Create a reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Created time for file in downloads folder "
            reasoning.test_event = test_event

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning

            # Test event for source URL
            source_url_test_event = LowLevelEvent()
            source_url_test_event.type = "URL Visit"
            source_url_test_event.path = "{}$".format(file_name)

            # Find matching events
            results = low_timeline.get_list_of_matches_in_sub_timeline({'source_url':source_url_test_event},start=each_event.date_time_min-15, end=each_event.date_time_min+15)

            if results:
                for each_match in results:
                    each_match_event = each_match[0] # the event
                    each_match_type = each_match[1] # source_url in this case

                    #update times for additional matched event
                    high_event.add_time(each_match_event.date_time_min)
                    high_event.add_time(each_match_event.date_time_max)

                    # update description
                    high_event.description = "File Downloaded ({}) from ({})".format(file_name, each_match_event.path)

                    #add as supporting artefacts
                    supporting = ReasoningArtefact()
                    supporting.description = "Found URL containing downloaded filename (%s)" % (each_match_event.path)
                    supporting.id = each_match_event.id
                    supporting.test_event = source_url_test_event
                    high_event.AddSupportingEvidenceArtefact(supporting)
            else:
                    #add as contradictory artefacts
                    contradictory = ReasoningArtefact()
                    contradictory.description = "Did not find URL containing downloaded filename"
                    contradictory.id = -1
                    contradictory.test_event = source_url_test_event
                    high_event.AddContradictoryEvidenceArtefact(contradictory)


            high_level_timeline.add_event(high_event)
