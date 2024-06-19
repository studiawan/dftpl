import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.LastShutdown import LastShutdown

# 2023-12-26 00:48:16.151380+00:00,Creation Time,EVT,WinEVTX,[1074 / 0x0432] Provider identifier: {b0aa8734-56f7-41cc-b2f4-de228e98b946} Source Name: User32 Strings: ['C:\\Windows\\System32\\RuntimeBroker.exe (WINDEV2311EVAL)'  'WINDEV2311EVAL'  'Other (Unplanned)'  '0x0'  'power off'  None  'WINDEV2311EVAL\\User'] Computer Name: WinDev2311Eval Record Number: 1896 Event Level: 4,winevtx,NTFS:\Windows\System32\winevt\Logs\System.evtx,-

@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:48:16.151380+00:00"
    event1.date_time_max = None
    event1.type = "Creation Time-EVT"
    event1.path = r"NTFS:\Windows\System32\winevt\Logs\System.evtx"
    event1.evidence = "[1074 / 0x0432] Provider identifier: {b0aa8734-56f7-41cc-b2f4-de228e98b946} Source Name: User32 Strings: ['C:\\Windows\\System32\\RuntimeBroker.exe (WINDEV2311EVAL)'  'WINDEV2311EVAL'  'Other (Unplanned)'  '0x0'  'power off'  None  'WINDEV2311EVAL\\User'] Computer Name: WinDev2311Eval Record Number: 1896 Event Level: 4"
    event1.plugin = "EVT-WinEVTX-winevtx"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:48:16.151380+00:00",
                      "Creation Time",
                      "EVT",
                      "WinEVTX",
                      "[1074 / 0x0432] Provider identifier: {b0aa8734-56f7-41cc-b2f4-de228e98b946} Source Name: User32 Strings: ['C:\\Windows\\System32\\RuntimeBroker.exe (WINDEV2311EVAL)'  'WINDEV2311EVAL'  'Other (Unplanned)'  '0x0'  'power off'  None  'WINDEV2311EVAL\\User'] Computer Name: WinDev2311Eval Record Number: 1896 Event Level: 4",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\System.evtx",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_LastShutdown(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = LastShutdown(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Shutdown time"
    assert high_timeline.events[0].description == "Windows shut down"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].device == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[0].keys["Windows Event ID"] == "1074"
    assert high_timeline.events[0].keys["Windows Event ID (hex)"] == "0x0432"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\System.evtx"
    assert high_timeline.events[0].supporting == {
        'before': [{
            'id': low_timeline.events[0].id,
            'date_time_min': low_timeline.events[0].date_time_min,
            'date_time_max': low_timeline.events[0].date_time_max,
            'type': low_timeline.events[0].type,
            'path': low_timeline.events[0].path,
            'evidence': low_timeline.events[0].evidence,
            'provenance': low_timeline.events[0].provenance,
            'plugin': low_timeline.events[0].plugin,
            'keys': low_timeline.events[0].keys
        }],
        'after': []
    }

    assert high_timeline.events[0].reasoning.id == 1
    assert high_timeline.events[0].reasoning.description == "Shutdown time found in NTFS:\\Windows\\System32\\winevt\\Logs\\System.evtx"
