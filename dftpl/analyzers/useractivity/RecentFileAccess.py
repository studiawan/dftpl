import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Recent File Access"
analyser_category = "User Activity"

def Run(timeline: LowLevelTimeline, start_id: int=0, end_id=None) -> HighLevelTimeline:
    """Runs the Recent File Access analyser"""
    if end_id == None:
        end_id = len(timeline.events)

    return RecentFileAccess(timeline, start_id, end_id)

def RecentFileAccess(low_timeline: LowLevelTimeline, start_id: int, end_id: int) -> HighLevelTimeline:
    """Finds recent file accesses"""
    
    # Get the test event dictionary
    test_event_dict = GetTestEventDictionary()
    
    # Create a high level timeline
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_with_test_event_dict(test_event_dict, start_id, end_id)

    if trigger_matches:
        for each_event in trigger_matches:
            # create high level event
            high_event = HighLevelEvent()
            high_event.id = each_event.id
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "Recent File Access"
            high_event.description = description
            high_event.category = analyser_category
            high_event.device = each_event.plugin
            high_event.files = each_event.path
            high_event.supporting = low_timeline.get_supporting_events(each_event.id)

            # get file details from trigger event
            file_details = GetMatchedFileDetailsFromTrigger(each_event)
            if file_details['file_details_from_lnk']:
                high_event.set_keys("file_details_from_lnk", file_details['file_details_from_lnk'])

            if file_details['file_details_from_entry_shell']:    
                high_event.set_keys("file_details_from_entry_shell", file_details['file_details_from_entry_shell'])

            # create reasoning artefact
            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = f"Recent file access: {each_event.path}"
            reasoning.test_event = ConvertTestEventToDict(test_event_dict) 
            reasoning.provenance = each_event.provenance

            # Add the reasoning artefact to the high level event
            high_event.trigger = reasoning.to_dict()
            
            # Add the high level event to the timeline
            high_timeline.add_event(high_event)

        return high_timeline


def GetTestEventDictionary() -> dict:
    """Returns list of test events"""

    # Windows shortcut or lnk file
    recent_from_lnk = LowLevelEvent()
    recent_from_lnk.plugin = "LNK-Windows Shortcut-custom_destinations/lnk"
    recent_from_lnk.type = "Creation Time-LNK"
    recent_from_lnk.evidence = (
        r"File size:.*?"
        r"File attribute flags:.*?"
        r"Drive type:.*?"
        r"Drive serial number:.*?"
        r"Volume label:.*?"
        r"Local path:.*?"
        r"cmd arguments:.*?"
        r"Icon location:.*?"
        r"Link target:.*?"
    )
    recent_from_lnk.path = r"\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\"

    # File entry shell item
    recent_from_entry_shell = LowLevelEvent()
    recent_from_entry_shell.plugin = "FILE-File entry shell item-custom_destinations/lnk/shell_items"
    recent_from_entry_shell.type = "Last Access Time-FILE"
    recent_from_entry_shell.evidence = (
        r"Name:.*?"
        r"Long name:.*?"
        r"NTFS file reference:.*?"
        r"Shell item path:.*?"
        r"Origin:.*?"
    )
    recent_from_entry_shell.path = r"\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\"

    # Return the test event dictionary
    test_event_dict = {
        "recent_from_lnk": recent_from_lnk,
        "recent_from_entry_shell": recent_from_entry_shell
    }

    return test_event_dict

def ConvertTestEventToDict(test_event: dict) -> dict:
    """Converts all test event dictionary elements to a dictionary"""
    test_event_dict = {
        "recent_from_lnk": {
            "plugin": test_event["recent_from_lnk"].plugin,
            "type": test_event["recent_from_lnk"].type,
            "evidence": test_event["recent_from_lnk"].evidence,
            "path": test_event["recent_from_lnk"].path
        },
        "recent_from_entry_shell": {
            "plugin": test_event["recent_from_entry_shell"].plugin,
            "type": test_event["recent_from_entry_shell"].type,
            "evidence": test_event["recent_from_entry_shell"].evidence,
            "path": test_event["recent_from_entry_shell"].path
        }
    }

    return test_event_dict

def GetMatchedFileDetailsFromTrigger(event: LowLevelEvent) -> dict:
    """Extracts file details from the trigger event"""
    file_details_dict = {
        'file_details_from_lnk': GetMatchedFileDetailsFromLNK(event.evidence),
        'file_details_from_entry_shell': GetMatchedFileDetailsFromEntryShell(event.evidence)
    }

    # return the extracted values
    return file_details_dict

def GetMatchedFileDetailsFromLNK(event: LowLevelEvent) -> dict:
    """Extracts file details from the trigger event"""
    file_details_dict = {}

    # Regular expressions to capture each value
    file_details_patterns = {
        "File size": re.compile(r'File size: (\d+)'),
        "File attribute flags": re.compile(r'File attribute flags: (0x[0-9a-fA-F]+)'),
        "Drive type": re.compile(r'Drive type: (\d+)'),
        "Drive serial number": re.compile(r'Drive serial number: (0x[0-9a-fA-F]+)'),
        "Volume label": re.compile(r'Volume label: ([^\s]+)'),
        "Local path": re.compile(r'Local path: ([\w:\\\s]+\.exe)'),
        "cmd arguments": re.compile(r'cmd arguments: ([^I]+)'),
        "Icon location": re.compile(r'Icon location: ([\w:\\\s]+\.exe)'),
        "Link target": re.compile(r'Link target: (<[\w\s]+> [^\n]+)')
    }

    # Extracting the values
    file_details_dict = {}
    for key, pattern in file_details_patterns.items():
        match = pattern.search(event)
        if match:
            file_details_dict[key] = match.group(1).rstrip()

    # return the extracted values
    return file_details_dict

def GetMatchedFileDetailsFromEntryShell(event: LowLevelEvent) -> dict:
    """Extracts file details from the entry shell event"""
    file_details_dict = {}

    # Define the regex patterns for each value
    patterns = {
        "Name": r"Name: ([^\s]+)",
        "Long name": r"Long name: ([^\s]+)",
        "NTFS file reference": r"NTFS file reference: ([^\s]+)",
        "Shell item path": r"Shell item path: ([^,]+) Origin",
        "Origin": r"Origin: ([^\s]+)"
    }

    # Extract the values
    file_details_dict = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, event)
        if match:
            file_details_dict[key] = match.group(1)
    
    return file_details_dict