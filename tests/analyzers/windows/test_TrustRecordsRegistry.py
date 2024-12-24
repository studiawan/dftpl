import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.TrustRecordsRegistry import FindTrustRecordsRegistry


@pytest.fixture
def low_timeline():
    # create a test event to match against

    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-12-09T04:08:42.712388+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Users\User\NTUSER.DAT"
    event1.evidence = r"[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords] %USERPROFILE%/Documents/Template%20II.pptx: [REG_BINARY] (24 bytes) file:///D:/Documents/Theory.ppt: [REG_BINARY] (24 bytes) file:///D:/Documents/Digital%20Forensics.pptx: [REG_BINARY] (24 bytes) file:///D:/Documents/Drone.pptx: [REG_BINARY] (24 bytes) file:///D:/Documents/Anti.odp: [REG_BINARY] (24 bytes) file:///D:/Documents/Graph%20Database.pptx: [REG_BINARY] (24 bytes)"
    event1.plugin = "REG-Registry Key-winreg/winreg_default"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-12-09T04:08:42.712388+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords] %USERPROFILE%/Documents/Template%20II.pptx: [REG_BINARY] (24 bytes) file:///D:/Documents/Theory.ppt: [REG_BINARY] (24 bytes) file:///D:/Documents/Digital%20Forensics.pptx: [REG_BINARY] (24 bytes) file:///D:/Documents/Drone.pptx: [REG_BINARY] (24 bytes) file:///D:/Documents/Anti.odp: [REG_BINARY] (24 bytes) file:///D:/Documents/Graph%20Database.pptx: [REG_BINARY] (24 bytes)"
                      "winreg/winreg_default",
                      r"NTFS:\Users\User\NTUSER.DAT",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindTrustRecordsRegistry(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindTrustRecordsRegistry(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Trust Records Registry Key"
    assert high_timeline.events[0].description == "Update time for 'PowerPoint' 16.0 trusted documents list with 6 entries"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].plugin == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].keys["Key Path"] == r"HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords"
    assert high_timeline.events[0].keys["Office Version"] == "16.0"
    assert high_timeline.events[0].keys["Office Application"] == "PowerPoint"
    assert high_timeline.events[0].keys["File1 Path"] == "%USERPROFILE%/Documents/Template%20II.pptx"
    assert high_timeline.events[0].keys["File2 Path"] == "file:///D:/Documents/Theory.ppt"
    assert high_timeline.events[0].keys["File3 Path"] == "file:///D:/Documents/Digital%20Forensics.pptx"
    assert high_timeline.events[0].keys["File4 Path"] == "file:///D:/Documents/Drone.pptx"
    assert high_timeline.events[0].keys["File5 Path"] == "file:///D:/Documents/Anti.odp"
    assert high_timeline.events[0].keys["File6 Path"] == "file:///D:/Documents/Graph%20Database.pptx"
    assert high_timeline.events[0].files == r"NTFS:\Users\User\NTUSER.DAT"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Update time for 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords' registry key with 6 entries found in 'NTFS:\Users\User\NTUSER.DAT'",
        'test_event': {
            'type': "Content Modification Time-REG",
            'evidence': r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\S*?\\'
                           r'(?:PowerPoint|Excel|Word)\\Security\\Trusted Documents\\TrustRecords\]'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://www.bleepingcomputer.com/news/security/windows-registry-helps-find-malicious-docs-behind-infections/',
        'keys': {},
    }




