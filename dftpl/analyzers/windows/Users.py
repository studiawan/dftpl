# Clement : Authorship is copied from other files.
__author__ = ['Jony Patterson', 'Hudan Studiawan']

"""
Changes :
1. Change character for paths to `\` from `/`.
2. Replace classes for both types of event, reason artefact, and high level timelines.
3. Removed unused classes.
4. Redefine methods accordingly.
5. Update test event declaration based on output from a recent version of plaso.
"""

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Creation of User"
analyser_category = "Windows"


def Run(low_timeline, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(low_timeline.events)
    return CreatedUser(low_timeline, start_id, end_id)

def CreatedUser(low_timeline, start_id, end_id):
    # Test event for entry in SAM for a user
    test_event = LowLevelEvent()
    test_event.plugin = "REG-Registry Key-winreg/winreg_default"
    test_event.type = "Content Modification Time-REG"
    # SAM path is in the "evidence" variable"
    test_event.evidence = r"\\SAM\\Domains\\Account\\Users\\Names\\.+$"
    # XP - \\SAM\\SAM\\Domains\\Acounts\\USers\\Names\\Username in Reg
    # 7 - \\CMI-CreativeHive{GUID}\\SAM\\Doains\\Account\\Users\\Names\\Username in Reg

    # Test event for creation of folder in \Users
    test_event2 = LowLevelEvent()
    test_event2.plugin = "FILE-File stat-filestat"
    test_event2.type = "Creation Time-FILE"
    test_event2.evidence = r"\\Users\\.[^\\]+$"


    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Clement's comments start
    # Original Code Assumption :
    # 1. Finds both SAM entry modification events and user folder creation events.
    # 2. Iterate through both sets of events.
    # 3. Finds SAM entry events.
    # 4. Searches for user folder creation event with the same username.
    #       Found : One potential scenario is the user logs in into new user account at least once.
    #       Not found : Potential scenario is after creation, user account hasn't been used.
    # Create 2 list for both types of events. Since new function only matches 1 test event at a time.
    # Clement's comments end
    trigger_matches_sam = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)
    trigger_matches_folder = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event2)

    for each_low_event in trigger_matches_sam:
        # TODO : No need to match again? Matching already done in LowLevelTimeline.find_matching_events_in_id_range.
        if each_low_event.match(test_event):
            high_event = HighLevelEvent()
            high_event.id = each_low_event.id
            high_event.add_time(each_low_event.date_time_min)
            high_event.evidence_source = each_low_event.evidence
            high_event.type = "User created"
            # Assume evidence/message from plaso for the matched event always starts with this format :
            # [HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\{Username here}]
            # Regex below with match from "\SAM" until "{username}]", removed the trailing '\', then extracts the username.
            high_event.set_keys("Username", re.search(r'\\SAM\\Domains\\Account\\Users\\Names\\.+?]', each_low_event.evidence).group().rstrip(']').split('\\')[-1])
            high_event.description = "User '%s' created" % high_event.keys["Username"]
            high_event.category = analyser_category
            high_event.device = each_low_event.plugin
            high_event.files = each_low_event.path
            high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)
            reasoning = ReasoningArtefact()
            reasoning.id = each_low_event.id
            #reasoning.description = "Last Write for SAM Registry entry " + each_low_event.path + " in " + each_low_event.provenance['raw_entry']
            reasoning.description = f"Last Write for SAM Registry entry {each_low_event.path} in {','.join(each_low_event.provenance['raw_entry'])}"
            reasoning.test_event = test_event
            high_event.trigger = reasoning

            # TODO : If stored in "supporting" library, add function in HighLevelEvent.py to abstract away the addition process.
            # TODO : Otherwise, modify time for getting supporting event to also capture folder creation/create separate analyzer for folder creation.
            # NOTE : Currently (15-07-2024) Folder creation event is stored as a LowLevelEvent class, not a ReasoningArtefact class like the original code.
            # Search for user folder creation event with the same username as current SAM event.
            folder_creation_results = SearchForFolderCreation(trigger_matches_folder, high_event.keys["Username"])
            if folder_creation_results:
                # evidence = ReasoningArtefact()
                # evidence.id = folder_creation_results.id
                # evidence.description = "Folder %s Created" % folder_creation_results.path
                # evidence.test_event = test_event2
                high_event.supporting['after'].append(folder_creation_results.to_dict())
            # Note : Contradictory artifacts is not used.
            high_timeline.add_event(high_event)

    return high_timeline

# Clement's comments START
# Reason for replacement : Based on recording and plaso results, folder creation
# event that matches the regex occured when user logged in using the new account.
# Therefore, i believe that the event can occur more than 5 minutes after account creation.

"""
Only returns folder creating event with the same username. Otherwise doesn't return anything.
"""
def SearchForFolderCreation(trigger_matches_folder, username):
    if len(trigger_matches_folder) < 1:
        return None
    else:
        for event in trigger_matches_folder:
            if event.path.split('\\')[-1] == username:
                return event
        return None
"""
def SearchForFolderCreation(low_event, low_timeline, username):
    start_date = low_event.date_time_min - (60*5) # minus 5 mins
    end_date = low_event.date_time_max + (60*5) # plus 5 mins

    # Test event checks if
    test_event2 = PyDFT.Events.LowLevelEvent.low_level_event()
    test_event2.plugin = "Mounted File System|MFT"
    test_event2.type = "Created"
    test_event2.path = "\\Users\\" + username

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
"""
# Clement's comments end