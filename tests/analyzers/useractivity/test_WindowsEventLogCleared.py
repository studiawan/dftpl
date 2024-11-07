import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.WindowsEventLogCleared import FindWindowsEventLogCleared

@pytest.fixture
def low_timeline():
    # Create 2 test event for windows event log artifacts
    event1 = LowLevelEvent()
    event1.id = 2
    event1.date_time_min = "2023-12-27T00:40:31.258240+00:00"
    event1.date_time_max = None
    event1.type = "Creation Time-EVT"
    event1.path = r"NTFS:\Windows\System32\winevt\Logs\System.evtx"
    event1.evidence = "[104 / 0x0068] Provider identifier: {fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148} Source Name: Microsoft-Windows-Eventlog Strings: ['User'  'WINDEV2311EVAL'  'Application'  '\\\\WINDEV2311EVAL\\C$\\Users\\User\\Documents\\app-event-log.evtx'  '3500'  '3096224743817719'] Computer Name: WinDev2311Eval Record Number: 1747 Event Level: 4"
    event1.plugin = "EVT-WinEVTX-winevtx"
    event1.provenance = {
        'line_number': 2,
        'raw_entry': ["2023-12-27T00:40:31.258240+00:00",
                      "Creation Time",
                      "EVT",
                      "WinEVTX",
                      "[104 / 0x0068] Provider identifier: {fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148} Source Name: Microsoft-Windows-Eventlog Strings: ['User'  'WINDEV2311EVAL'  'Application'  '\\\\WINDEV2311EVAL\\C$\\Users\\User\\Documents\\app-event-log.evtx'  '3500'  '3096224743817719'] Computer Name: WinDev2311Eval Record Number: 1747 Event Level: 4",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\System.evtx",
                      "-"]
    }
    event1.keys = None

    event2 = LowLevelEvent()
    event2.id = 1
    event2.date_time_min = "2023-11-15T19:15:11.309955+00:00"
    event2.date_time_max = None
    event2.type = "Creation Time-EVT"
    event2.path = r"NTFS:\Windows\System32\winevt\Logs\Security.evtx"
    event2.evidence = "[1102 / 0x044e] Provider identifier: {fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148} Source Name: Microsoft-Windows-Eventlog Strings: ['S-1-5-21-2939114745-2192642559-1429779423-500'  'Administrator'  'WINDEVEVAL'  '0x000000000005ce5e'  '1148'  '2533274790396089'] Computer Name: WinDevEval Record Number: 2577 Event Level: 4"
    event2.plugin = "EVT-WinEVTX-winevtx"
    event2.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-11-15T19:15:11.309955+00:00",
                      "Creation Time",
                      "EVT",
                      "WinEVTX",
                      "[1102 / 0x044e] Provider identifier: {fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148} Source Name: Microsoft-Windows-Eventlog Strings: ['S-1-5-21-2939114745-2192642559-1429779423-500'  'Administrator'  'WINDEVEVAL'  '0x000000000005ce5e'  '1148'  '2533274790396089'] Computer Name: WinDevEval Record Number: 2577 Event Level: 4",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\Security.evtx",
                      "-"]
    }
    event2.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event2)
    timeline.add_event(event1)

    return timeline

def test_WindowsEventLogCleared104(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindWindowsEventLogCleared(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].type == "Windows Event Log Cleared"
    assert high_timeline.events[0].description == "Windows Event Log Cleared for 'Application' log."
    assert high_timeline.events[0].category == "User Activity"
    assert high_timeline.events[0].plugin == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[0].keys["SubjectUserName"] == "User"
    assert high_timeline.events[0].keys["SubjectDomainName"] == "WINDEV2311EVAL"
    assert high_timeline.events[0].keys["Channel"] == "Application"
    assert high_timeline.events[0].keys["BackupPath"] == "\\\\WINDEV2311EVAL\\C$\\Users\\User\\Documents\\app-event-log.evtx"
    assert high_timeline.events[0].keys["ClientProcessId"] == "3500"
    assert high_timeline.events[0].keys["ClientProcessStartKey"] == "3096224743817719"
    assert high_timeline.events[0].keys["ComputerName"] == "WinDev2311Eval"
    assert high_timeline.events[0].keys["RecordNumber"] == "1747"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\System.evtx"
    assert len(high_timeline.events[0].supporting['before']) == 1
    assert len(high_timeline.events[0].supporting['after']) == 0

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[1].id,
        'description': "Windows Event Log Cleared for 'Application' log found in 'NTFS:\Windows\System32\winevt\Logs\System.evtx' with event id '104'.",
        'test_event': {
            'type': low_timeline.events[1].type,
                'evidence': r"^\[104 \/.+\] Provider identifier: {.+} Source Name: Microsoft-Windows-Eventlog"
        },
        'provenance': low_timeline.events[1].provenance,
        'references': 'https://docs.logrhythm.com/devices/docs/v-2-0-evid-104-eventlog-log-file-cleared',
        'keys': {},
    }


def test_WindowsEventLogCleared1102(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindWindowsEventLogCleared(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[1].type == "Windows Event Log Cleared"
    assert high_timeline.events[1].description == "Windows Event Log Cleared for 'Security' log."
    assert high_timeline.events[1].category == "User Activity"
    assert high_timeline.events[1].plugin == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[1].keys["SubjectUserSid"] == "S-1-5-21-2939114745-2192642559-1429779423-500"
    assert high_timeline.events[1].keys["SubjectUserName"] == "Administrator"
    assert high_timeline.events[1].keys["SubjectDomainName"] == "WINDEVEVAL"
    assert high_timeline.events[1].keys["SubjectLogonId"] == "0x000000000005ce5e"
    assert high_timeline.events[1].keys["ClientProcessId"] == "1148"
    assert high_timeline.events[1].keys["ClientProcessStartKey"] == "2533274790396089"
    assert high_timeline.events[1].keys["ComputerName"] == "WinDevEval"
    assert high_timeline.events[1].keys["RecordNumber"] == "2577"
    assert high_timeline.events[1].files == r"NTFS:\Windows\System32\winevt\Logs\Security.evtx"
    assert len(high_timeline.events[1].supporting['before']) == 0
    assert len(high_timeline.events[1].supporting['after']) == 1

    assert high_timeline.events[1].trigger == {
        'id': low_timeline.events[0].id,
        'description': "Windows Event Log Cleared for 'Security' log found in 'NTFS:\Windows\System32\winevt\Logs\Security.evtx' with event id '1102'.",
        'test_event': {
            'type': low_timeline.events[0].type,
                'evidence': r"^\[1102 \/.+\] Provider identifier: {.+} Source Name: Microsoft-Windows-Eventlog"
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102',
        'keys': {},
    }
