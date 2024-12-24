import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.ServiceInstalled import FindServiceInstalled


@pytest.fixture
def low_timeline():
    # create a test event to match against

    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-08-29T07:54:11.402180+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-EVT"
    event1.path = r"NTFS:\Windows\System32\winevt\Logs\System.evtx"
    event1.evidence = r"[7045 / 0x1b85] Provider identifier: {555908d1-a6d7-4695-8e1e-26931d2012f4} Source Name: Service Control Manager Strings: ['WPD File System driver'  '\\SystemRoot\\system32\\DRIVERS\\WUDFRd.sys'  'kernel mode driver'  'demand start'  None] Computer Name: WinDev2404Eval Record Number: 1999 Event Level: 4 Message string: A service was installed in the system.\n\nService Name:  WPD File System driver\nService File Name:  \SystemRoot\system32\DRIVERS\WUDFRd.sys\nService Type:  kernel mode driver\nService Start Type:  demand start\nService Account:  "
    event1.plugin = "EVT-WinEVTX-winevtx"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T07:54:11.402180+00:00",
                      "Content Modification Time",
                      "EVT",
                      "WinEVTX",
                      r"[7045 / 0x1b85] Provider identifier: {555908d1-a6d7-4695-8e1e-26931d2012f4} Source Name: Service Control Manager Strings: ['WPD File System driver'  '\\SystemRoot\\system32\\DRIVERS\\WUDFRd.sys'  'kernel mode driver'  'demand start'  None] Computer Name: WinDev2404Eval Record Number: 1999 Event Level: 4 Message string: A service was installed in the system.\n\nService Name:  WPD File System driver\nService File Name:  \SystemRoot\system32\DRIVERS\WUDFRd.sys\nService Type:  kernel mode driver\nService Start Type:  demand start\nService Account:  ",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\System.evtx",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindServiceInstalled(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindServiceInstalled(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Service Installed"
    assert high_timeline.events[0].description == "Service installed with name 'WPD File System driver' by account 'None'"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].plugin == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[0].keys["Service Name"] == "WPD File System driver"
    assert high_timeline.events[0].keys["Image Path"] == r"\\SystemRoot\\system32\\DRIVERS\\WUDFRd.sys"
    assert high_timeline.events[0].keys["Service Type"] == "kernel mode driver"
    assert high_timeline.events[0].keys["Start Type"] == "demand start"
    assert high_timeline.events[0].keys["Account Name"] == "None"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\System.evtx"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Service installed with path '\\SystemRoot\\system32\\DRIVERS\\WUDFRd.sys' found by 'Service Control Manager' with event id 7045 in path 'NTFS:\Windows\System32\winevt\Logs\System.evtx'",
        'test_event': {
            'type': "Content Modification Time-EVT",
            'evidence': r'^\[7045 \/ 0x1b85\]'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://research.splunk.com/endpoint/429141be-8311-11eb-adb6-acde48001122/',
        'keys': {},
    }




