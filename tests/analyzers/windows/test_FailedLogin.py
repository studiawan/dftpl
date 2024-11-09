import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.FailedLogin import FindFailedLogin


@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:34:47.890403+00:00"
    event1.date_time_max = None
    event1.type = "Creation Time-EVT"
    event1.path = r"NTFS:\Windows\System32\winevt\Logs\Security.evtx"
    event1.evidence = r"[4625 / 0x1211] Provider identifier: {54849625-5478-4994-a5ba-3e3b0328c30d} Source Name: Microsoft-Windows-Security-Auditing Strings: ['S-1-5-18'  'WINDEV2311EVAL$'  'WORKGROUP'  '0x00000000000003e7'  'S-1-0-0'  'root'  'WINDEV2311EVAL'  '0xc000006d'  '%%2313'  '0xc000006a'  '2'  'User32 '  'Negotiate'  'WINDEV2311EVAL'  '-'  '-'  '0'  '0x0000000000000de0'  'C:\\Windows\\System32\\svchost.exe'  '127.0.0.1'  '0'] Computer Name: WinDev2311Eval Record Number: 3332 Event Level: 0"
    event1.plugin = "EVT-WinEVTX-winevtx"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26T23:33:11.631160+00:00",
                      "Creation Time",
                      "EVT",
                      "WinEVTX",
                      r"[4625 / 0x1211] Provider identifier: {54849625-5478-4994-a5ba-3e3b0328c30d} Source Name: Microsoft-Windows-Security-Auditing Strings: ['S-1-5-18'  'WINDEV2311EVAL$'  'WORKGROUP'  '0x00000000000003e7'  'S-1-0-0'  'root'  'WINDEV2311EVAL'  '0xc000006d'  '%%2313'  '0xc000006a'  '2'  'User32 '  'Negotiate'  'WINDEV2311EVAL'  '-'  '-'  '0'  '0x0000000000000de0'  'C:\\Windows\\System32\\svchost.exe'  '127.0.0.1'  '0'] Computer Name: WinDev2311Eval Record Number: 3332 Event Level: 0",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\Security.evtx",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindFailedLogin(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindFailedLogin(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Failed Login"
    assert high_timeline.events[0].description == "Failed login attempt on username 'root'"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[0].keys["SubjectSid"] == "S-1-5-18"
    assert high_timeline.events[0].keys["SubjectUserName"] == "WINDEV2311EVAL$"
    assert high_timeline.events[0].keys["TargetUserSid"] == 'S-1-0-0'
    assert high_timeline.events[0].keys["TargetUserName"] == 'root'
    assert high_timeline.events[0].keys["TargetDomainName"] == 'WINDEV2311EVAL'
    assert high_timeline.events[0].keys["Status"] == '0xc000006d'
    assert high_timeline.events[0].keys["SubStatus"] == '0xc000006a'
    assert high_timeline.events[0].keys["LogonType"] == '2 - Interactive - A user logged on to this computer.'
    assert high_timeline.events[0].keys["RecordNumber"] == "3332"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\Security.evtx"
    assert high_timeline.events[0].supporting == {
        'before': [],
        'after': [],
    }

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': f"Failed login attempt on username 'root' found with Windows event ID 4625",
        'test_event': {
            'type': low_timeline.events[0].type,
            'evidence': r'^\[4625 \/.+\] Provider identifier: {.+} Source Name: Microsoft-Windows-Security-Auditing'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625',
        'keys': {},
    }
