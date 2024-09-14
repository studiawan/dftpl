# TODO : Missing Authorship
# TODO : Argument type hints
import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

# 2024-04-17T01:16:00.609890+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards\2] Description: [REG_SZ] Intel(R) PRO/1000 MT Desktop Adapter ServiceName: [REG_SZ] {9F272040-23C5-42CB-BBB3-EBCA31FB81C8},winreg/winreg_default,NTFS:\Windows\System32\config\SOFTWARE,-

description = "Network Interfaces"
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Network Interfaces analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    return NetworkCards(low_timeline, start_id, end_id)


def FindNetworkCards(low_timeline, start_id, end_id):
    """Searches for the installation of network interfaces"""
    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    test_event = LowLevelEvent()
    # TODO : Is the plugin value still used or is it enough to only compare the type and evidence?
    # test_event.plugin = "Registry Parser"
    test_event.type = "Content Modification Time-REG"
    # Registry path is stored in "evidence"
    test_event.evidence = r"\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\[^\\]*?$"

    # TODO : Can these value be blank?
    # Clement : For now, assume that event is valid even if these key values are blank.
    # Suggestion : If blank, add warning to output data that the values have been tampered with?
    # Old code :
    # test_event.set_keys("Description", ".*")
    # test_event.set_keys("ServiceName", ".*")

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_low_event in trigger_matches:
        # TODO : No need to match again? Matching already done in LowLevelTimeline.find_matching_events_in_id_range.
        if each_low_event.match(test_event):
            # Retrieve key value from low level event, then compare to test_event before continuing assignment
            high_event = HighLevelEvent()
            # NEW : Add id
            high_event.id = each_low_event.id
            high_event.add_time(each_low_event.date_time_min)
            high_event.type = "Network Card Installation"
            high_event.evidence_source = each_low_event.evidence
            high_event.category = analyser_category
            high_event.device = each_low_event.plugin

            # NEW : Since low level events doesn't have keys, manually parse low level evidence for the keys.
            # Regex used to capture each keys : (\w+)(?:: )(.+?)(?=(?:(?:\w+)(?:: ))|$)
            # (\w+) = 1st capturing group. Captures key name
            # (?:: ) = Skip over ": "
            # (.+?) = 2nd capturing group. Captures key value. With positive lookahead, will capture until character before the next key name, usually a single space " ".
            # (?=(?:(?:\w+)(?:: ))|$) = Positive lookahead to check if there's another keyname after 2nd capturing group or end of string.
            key_name: str
            key_value: str
            for key_name, key_value in re.findall(r'(\w+)(?:: )(.+?)(?=(?:(?:\w+)(?:: ))|$)', each_low_event.evidence):
                high_event.set_keys(key_name, key_value.rstrip())
            print()
            high_event.description = "Network card %s was installed" % high_event.keys["Description"]
            # NEW : File value
            high_event.files = each_low_event.path
            # NEW : Get surrounding events
            high_event.supporting = low_timeline.get_supporting_events(each_low_event.id)

            reasoning = ReasoningArtefact()
            reasoning.id = each_low_event.id
            reasoning.test_event = test_event
            # NEW : Regex to extract registry path information
            # Extracts path between first set of angle brackets.
            reasoning.description = f"Registry entry modification event found in {','.join(each_low_event.provenance['raw_entry'])}"
            reasoning.provenance = each_low_event.provenance
            # Add the reasoning artefact to the high level event

            high_event.trigger = reasoning.to_dict()

            high_timeline.add_event(high_event)

    return high_timeline
