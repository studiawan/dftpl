import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.ProcessCreation import FindProcessCreation


@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:34:47.890403+00:00"
    event1.date_time_max = None
    event1.type = "Creation Time-EVT"
    event1.path = r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx"
    event1.evidence = "[9707 / 0x25eb] Provider identifier: {30336ed4-e327-447c-9de0-51b652c86108} Source Name: Microsoft-Windows-Shell-Core Strings: ['msedge.exe"" --no-startup-window --win-session-start'] Computer Name: WinDev2311Eval Record Number: 2249 Event Level: 4"
    event1.plugin = "EVT-WinEVTX-winevtx"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:34:47.890403+00:00",
                      "Content Modification Time",
                      "EVT",
                      "WinEVTX",
                      "[9707 / 0x25eb] Provider identifier: {30336ed4-e327-447c-9de0-51b652c86108} Source Name: Microsoft-Windows-Shell-Core Strings: ['msedge.exe"" --no-startup-window --win-session-start'] Computer Name: WinDev2311Eval Record Number: 2249 Event Level: 4",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindProcessCreation(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindProcessCreation(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Process Creation"
    assert high_timeline.events[0].description == "Process creation of 'msedge.exe'"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[0].keys["Windows Event ID"] == "9707"
    assert high_timeline.events[0].keys["Windows Event ID (hex)"] == "0x25eb"
    assert high_timeline.events[0].keys["Executable name"] == "msedge.exe"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx"
    assert high_timeline.events[0].supporting == {
        'before': [],
        'after': [],
    }

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': f"Process creation event of 'msedge.exe' found with Windows event ID 9707",
        'test_event': {
            'type': low_timeline.events[0].type,
            'evidence': r'\[\s*(9707|0x25eb)\s*/\s*(9707|0x25eb)\s*\].*\'([^\']+\.exe)'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://github.com/Psmths/windows-forensic-artifacts/blob/main/execution/evtx-9707-shell-core.md',
        'keys': {},
    }
