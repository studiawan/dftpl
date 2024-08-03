# TODO : Missing Authorship

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

# 2024-07-12T05:50:14.347797+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{400F2E8B-9AB8-4DA6-8705-455176209E17}] Category: [REG_DWORD_LE] 0 DateCreated: [REG_BINARY] (16 bytes) DateLastConnected: [REG_BINARY] (16 bytes) Description: [REG_SZ] Network Managed: [REG_DWORD_LE] 0 NameType: [REG_DWORD_LE] 6 ProfileName: [REG_SZ] Network,winreg/winreg_default,NTFS:\Windows\System32\config\SOFTWARE,-

description = "Network Profiles"
analyser_category = "Windows"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Network Profiles analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    return NetworkProfilesWin7(low_timeline, start_id, end_id)


# NOTE : Changes made for logs from windows 11 (3th quarter of 2024)
def FindNetworkProfiles(low_timeline, start_id, end_id):
    """Searches for times associated with network profiles"""
    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    test_event = LowLevelEvent()
    # TODO : Is the "plugin" value still used or is it enough to only compare the type and evidence?
    #test_event.plugin = "Registry Parser"
    test_event.type = "Content Modification Time-REG"
    # Registry path is stored in "evidence"
    # TODO : Should the regex check if there's an ID directory or not? (From klein closure to positive closure).
    test_event.evidence = r"\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{.*?}"

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)


    for each_low_event in trigger_matches:
        if each_low_event.match(test_event):
            # TODO : "DateCreated", "DateLastConnected", and "DefaultGatewayMac" key values can only be obtained with json output format. Add after json input support is implemented.
            # TODO : Find trusted/official references to intrepet values for "Category", "Manages", and "NameType" keys. Closest source for "Category" is https://www.geeksforgeeks.org/how-to-change-network-settings-of-window-from-public-to-private/
            # NOTE : Tested to work with plaso release 25-12-2023. Doesn't work with plaso most recent release by 27-07-2024 since in json format, where the binary/hex should be, only the string "{encoded_value:s}" is found.
            # REF : https://github.com/log2timeline/plaso/commit/97a7f95de08e75a929d12a28c3ebc3013871f3e0
            # created = each_low_event.keys["DateCreated"]
            # created_unix_time = PyDFT.Utilities.TimeCore.Convert128BitWindowsSYSTEMStringToUnixTime(created)
            # last_connected = each_low_event.keys["DateLastConnected"]
            # last_connected_unix_time = PyDFT.Utilities.TimeCore.Convert128BitWindowsSYSTEMStringToUnixTime(last_connected)

            # Make event for first connection
            high_event1 = HighLevelEvent()
            high_event1.id = each_low_event.id
            # NEW : Since low level events doesn't have keys, manually parse low level evidence for the keys.
            # Regex used to capture each keys : (\w+)(?:: )(.+?)(?=(?:(?:\w+)(?:: ))|$)
            # (\w+) = 1st capturing group. Captures key name
            # (?:: ) = Skip over ": "
            # (.+?) = 2nd capturing group. Captures key value. With positive lookahead, will capture until character before the next key name, usually a single space " ".
            # (?=(?:(?:\w+)(?:: ))|$) = Positive lookahead to check if there's another keyname after 2nd capturing group or end of string.

            # Trying out annotation for loop variables.

            key_name: str
            key_value: str
            for key_name, key_value in re.findall(r'(\w+)(?:: )(.+?)(?=(?:(?:\w+)(?:: ))|$)', each_low_event.evidence):
                high_event1.set_keys(key_name, key_value.rstrip())

            # NEW : Default event date time for placeholder
            high_event1.add_time(each_low_event.date_time_min)
            # high_event1.add_time(created_unix_time)
            # high_event1.add_time(last_connected_unix_time)
            high_event1.type = "Network Connection"
            high_event1.evidence_source = each_low_event.evidence
            # NEW : Regex to extract value without registry data type.
            high_event1.description = "Network Profile '%s' possibly in use" % re.findall(r'^(?:\[.+\] )(.+)', high_event1.keys["ProfileName"])[0]
            high_event1.category = analyser_category
            high_event1.device = each_low_event.plugin
            # NEW : File value
            high_event1.files = each_low_event.path

            # NEW : Get surrounding events
            high_event1.supporting = low_timeline.get_supporting_events(each_low_event.id)

            reasoning = ReasoningArtefact()
            reasoning.id = each_low_event.id
            reasoning.test_event = test_event
            reasoning.description = f"Registry entry for network profile found in {','.join(each_low_event.provenance['raw_entry'])}"
            high_event1.trigger = reasoning

            high_event1.set_keys("ProfileGUID", re.search(r"\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{(.*?)}", each_low_event.evidence).group(1))

            #-------------------------------------

            #reasoning = PyDFT.Core.HighLevelEvent.ReasoningArtefact()
            #reasoning.id = each_low_event.id
            #reasoning.test_event = test_event
            #reasoning.description = "Registry entry %s DateLastConnected value" % each_low_event.path
            #high_event1.AddSupportingEvidenceArtefact(reasoning)

            # -------------------------------------
            # TODO : Test for DefaultGatewayMac after json input support or windows registry binary support added for all formats.
            # Make test sub event with Profile GUID
            # sub_test_event = PyDFT.Events.LowLevelEvent.low_level_event()
            # sub_test_event.keys["ProfileGuid"] = high_event1.keys["ProfileGUID"]
            #
            # # Test for this event in a sub timeline
            # sub_timeline = low_timeline.get_events_between_datetimes(created_unix_time-60, created_unix_time+60)
            # for each_sub_event in sub_timeline:
            #     if each_sub_event.match(sub_test_event):
            #         # If found add as a supporting artefact
            #         high_event1.keys["Gateway_MAC"] = each_sub_event.keys["DefaultGatewayMac"]
            #
            #         supporting = PyDFT.Events.HighLevelReasoningArtefact.ReasoningArtefact()
            #         supporting.id = each_sub_event.id
            #         supporting.test_event = sub_test_event
            #         supporting.description = "Profile GUID matched in %s" % each_sub_event.path
            #         high_event1.AddSupportingEvidenceArtefact(supporting)
            #
            # # Add the events to the timeline
            # high_level_timeline.add_event(high_event1)
            high_timeline.add_event(high_event1)

    return high_timeline