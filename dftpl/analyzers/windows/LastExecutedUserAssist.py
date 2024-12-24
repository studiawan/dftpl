# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Last Time Executed (Registry UserAssist)"
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Last Time Executed (Registry UserAssist) analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindLastExecutedUserAssist(low_timeline, start_id, end_id)

def FindLastExecutedUserAssist(low_timeline, start_id, end_id):
    """Finds UserAssist registry events based on event structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Last Time Executed-REG"
    test_event.evidence = r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\\{\S*\}\\Count'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        # Get values from evidence
        match = re.search(r'^\[(HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion'
                          r'\\Explorer\\UserAssist\\\{\S*\}\\Count)\] '
                          r'UserAssist entry: (\d+) Value name: (.+) Count: (\d+) '
                          r'Application focus count: (\d+) '
                          r'Application focus duration: (\d+)$', each_low_event.evidence)
        userassist_index = match.group(2)
        value_name = match.group(3)
        execution_count = match.group(4)
        focus_count = match.group(5)
        focus_duration = match.group(6)
        reg_path = match.group(1)

        # Create a high level event
        high_event = HighLevelEvent()
        high_event.id = each_low_event.id
        high_event.add_time(each_low_event.date_time_min)
        high_event.evidence_source = each_low_event.evidence
        # Either "Previous Last Time Executed" or "Last Time Executed"
        high_event.type = "Last Time Executed (Registry UserAssist)"
        high_event.description = f"Last Time Executed of '{value_name}' with {execution_count} execution count"
        high_event.category = analyser_category
        high_event.plugin = each_low_event.plugin
        high_event.files = each_low_event.path
        high_event.set_keys("UserAssist Entry", userassist_index)
        high_event.set_keys("Value Name", value_name)
        high_event.set_keys("Execution Count", execution_count)
        high_event.set_keys("Focus Count", focus_count)
        high_event.set_keys("Focus Duration", focus_duration)
        high_event.set_keys("Registry Path", reg_path)
        high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

        # Create a reasoning artefact
        reasoning = ReasoningArtefact()
        reasoning.id = each_low_event.id
        reasoning.description = f"Last Time Executed of '{value_name}' found at '{reg_path}' in '{each_low_event.path}'"
        reasoning.test_event = test_event
        reasoning.provenance = each_low_event.provenance
        reasoning.references = 'https://www.magnetforensics.com/blog/artifact-profile-userassist/'

        # Add the reasoning artefact to the high level event
        high_event.trigger = reasoning.to_dict()

        # Add the high level event to the high level timeline
        high_timeline.add_event(high_event)

    return high_timeline