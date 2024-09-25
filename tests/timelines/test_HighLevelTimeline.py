import pytest
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline

@pytest.fixture
def high_level_event():
    high_event = HighLevelEvent()
    high_event.id = 1
    high_event.date_time_min = "2023-12-26 00:34:47.890403+00:00"
    high_event.date_time_max = "2023-12-26 00:34:47.890403+00:00"
    high_event.type = "Process Creation"
    high_event.description = "Process creation of 'msedge.exe'"
    high_event.category = "Windows"
    high_event.plugin = "EVT-WinEVTX-winevtx"
    high_event.keys = {
        "Windows Event ID": "9707",
        "Windows Event ID (hex)": "0x25eb",
        "Executable name": "msedge.exe"
    }
    high_event.files = r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx"

    reasoning = ReasoningArtefact()
    reasoning.id = 1
    reasoning.description = "Process creation event found in 2023-12-26 00:34:47.890403+00:00,Content Modification Time,EVT,WinEVTX,[9707 / 0x25eb] Provider identifier: {30336ed4-e327-447c-9de0-51b652c86108} Source Name: Microsoft-Windows-Shell-Core Strings: ['msedge.exe --no-startup-window --win-session-start'] Computer Name: WinDev2311Eval Record Number: 2249 Event Level: 4,winevtx,NTFS:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Shell-Core%4Operational.evtx,-"

    high_event.reasoning = reasoning

    return high_event

def test_HighLevelTimeline(high_level_event):
    high_timeline = HighLevelTimeline()
    high_timeline.add_event(high_level_event)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].id == 1
    assert high_timeline.events[0].date_time_min == "2023-12-26 00:34:47.890403+00:00"
    assert high_timeline.events[0].date_time_max == "2023-12-26 00:34:47.890403+00:00"
    assert high_timeline.events[0].type == "Process Creation"
    assert high_timeline.events[0].description == "Process creation of 'msedge.exe'"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[0].keys == {
        "Windows Event ID": "9707",
        "Windows Event ID (hex)": "0x25eb",
        "Executable name": "msedge.exe"
    }
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx"
    assert high_timeline.events[0].reasoning.id == 1
    assert high_timeline.events[0].reasoning.description == "Process creation event found in 2023-12-26 00:34:47.890403+00:00,Content Modification Time,EVT,WinEVTX,[9707 / 0x25eb] Provider identifier: {30336ed4-e327-447c-9de0-51b652c86108} Source Name: Microsoft-Windows-Shell-Core Strings: ['msedge.exe --no-startup-window --win-session-start'] Computer Name: WinDev2311Eval Record Number: 2249 Event Level: 4,winevtx,NTFS:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Shell-Core%4Operational.evtx,-"

