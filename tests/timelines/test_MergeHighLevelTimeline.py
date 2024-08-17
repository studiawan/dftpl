import pytest
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline, MergeHighLevelTimeline

@pytest.fixture
def high_level_timelines():
    # Create high level event 1
    high_event1 = HighLevelEvent()
    high_event1.id = 1
    high_event1.date_time_min = "2023-12-26 00:34:47.890403+00:00"
    high_event1.date_time_max = "2023-12-26 00:34:47.890403+00:00"
    high_event1.type = "Process Creation"
    high_event1.description = "Process creation of 'msedge.exe'"
    high_event1.category = "Windows"
    high_event1.device = "EVT-WinEVTX-winevtx"
    high_event1.keys = {
        "Windows Event ID": "9707",
        "Windows Event ID (hex)": "0x25eb",
        "Executable name": "msedge.exe"
    }
    high_event1.files = r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx"

    reasoning1 = ReasoningArtefact()
    reasoning1.id = 1
    reasoning1.description = "Process creation event found in 2023-12-26 00:34:47.890403+00:00,Content Modification Time,EVT,WinEVTX,[9707 / 0x25eb] Provider identifier: {30336ed4-e327-447c-9de0-51b652c86108} Source Name: Microsoft-Windows-Shell-Core Strings: ['msedge.exe --no-startup-window --win-session-start'] Computer Name: WinDev2311Eval Record Number: 2249 Event Level: 4,winevtx,NTFS:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Shell-Core%4Operational.evtx,-"

    high_event1.reasoning = reasoning1

    # Create high level event 2
    high_event2 = HighLevelEvent()
    high_event2.id = 2
    high_event2.date_time_min = "2023-12-26 00:37:46.738362+00:00"
    high_event2.date_time_max = "2023-12-26 00:37:46.738362+00:00"
    high_event2.evidence_source = r"NTFS:\Windows\explorer.exe Type: file"
    high_event2.type = "Program opened"
    high_event2.description = "A Windows program was opened"
    high_event2.category = "System"
    high_event2.device = "FILE-File stat-filestat"
    high_event2.files = r"NTFS:\Windows\explorer.exe"
    high_event2.keys = None

    # Create high level event 3
    high_event3 = HighLevelEvent()
    high_event3.id = 3
    high_event3.date_time_min = "2023-12-26 00:36:59.234628+00:00"
    high_event3.date_time_max = "2023-12-26 00:36:59.234628+00:00"
    high_event3.evidence_source = r"NTFS:\Windows\System32\cmd.exe Type: file"
    high_event3.type = "Last Access Time-FILE"
    high_event3.description = "A Windows program was opened"
    high_event3.category = "System"
    high_event3.device = "FILE-File stat-filestat"
    high_event3.files = r"NTFS:\Windows\System32\cmd.exe"
    high_event3.keys = None

    # Create high level timelines
    high_timeline1 = HighLevelTimeline()
    high_timeline1.add_event(high_event1)
    high_timeline2 = HighLevelTimeline()
    high_timeline2.add_event(high_event2)
    high_timeline3 = HighLevelTimeline()
    high_timeline3.add_event(high_event3)

    # Add high level timelines to the list
    high_timelines = [high_timeline1, high_timeline2, high_timeline3]

    return high_timelines

def test_MergeHighLevelTimeline(high_level_timelines):
    merge_high_level_timeline = MergeHighLevelTimeline(high_level_timelines)
    merged_high_level_timeline = merge_high_level_timeline.merge()
    
    assert len(merged_high_level_timeline.events) == 3
    assert merged_high_level_timeline.events[0].id == 1
    assert merged_high_level_timeline.events[0].date_time_min == "2023-12-26 00:34:47.890403+00:00"
    assert merged_high_level_timeline.events[0].date_time_max == "2023-12-26 00:34:47.890403+00:00"
    assert merged_high_level_timeline.events[0].type == "Process Creation"
    assert merged_high_level_timeline.events[0].description == "Process creation of 'msedge.exe'"
    assert merged_high_level_timeline.events[0].category == "Windows"
    assert merged_high_level_timeline.events[0].device == "EVT-WinEVTX-winevtx"
    assert merged_high_level_timeline.events[0].keys == {
        "Windows Event ID": "9707",
        "Windows Event ID (hex)": "0x25eb",
        "Executable name": "msedge.exe"
    }
    assert merged_high_level_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx"
    assert merged_high_level_timeline.events[0].reasoning.id == 1
    assert merged_high_level_timeline.events[0].reasoning.description == "Process creation event found in 2023-12-26 00:34:47.890403+00:00,Content Modification Time,EVT,WinEVTX,[9707 / 0x25eb] Provider identifier: {30336ed4-e327-447c-9de0-51b652c86108} Source Name: Microsoft-Windows-Shell-Core Strings: ['msedge.exe --no-startup-window --win-session-start'] Computer Name: WinDev2311Eval Record Number: 2249 Event Level: 4,winevtx,NTFS:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Shell-Core%4Operational.evtx,-"

    assert merged_high_level_timeline.events[1].id == 3
    assert merged_high_level_timeline.events[1].date_time_min == "2023-12-26 00:36:59.234628+00:00"
    assert merged_high_level_timeline.events[1].date_time_max == "2023-12-26 00:36:59.234628+00:00"
    assert merged_high_level_timeline.events[1].evidence_source == r"NTFS:\Windows\System32\cmd.exe Type: file"
    assert merged_high_level_timeline.events[1].type == "Last Access Time-FILE"
    assert merged_high_level_timeline.events[1].description == "A Windows program was opened"
    assert merged_high_level_timeline.events[1].category == "System"
    assert merged_high_level_timeline.events[1].device == "FILE-File stat-filestat"
    assert merged_high_level_timeline.events[1].files == r"NTFS:\Windows\System32\cmd.exe"
    assert merged_high_level_timeline.events[1].keys == None