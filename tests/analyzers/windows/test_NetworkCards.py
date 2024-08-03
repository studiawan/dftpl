import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.NetworkCards import FindNetworkCards


@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-04-17T01:16:00.609890+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Windows\System32\config\SOFTWARE"
    event1.evidence = r"[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards\2] Description: [REG_SZ] Intel(R) PRO/1000 MT Desktop Adapter ServiceName: [REG_SZ] {9F272040-23C5-42CB-BBB3-EBCA31FB81C8}"
    event1.plugin = "REG-Registry Key-winreg/winreg_default"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-04-17T01:16:00.609890+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards\2] Description: [REG_SZ] Intel(R) PRO/1000 MT Desktop Adapter ServiceName: [REG_SZ] {9F272040-23C5-42CB-BBB3-EBCA31FB81C8}",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SOFTWARE",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindProcessCreation(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindNetworkCards(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Network Card Installation"
    assert high_timeline.events[0].description == "Network card [REG_SZ] Intel(R) PRO/1000 MT Desktop Adapter was installed"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].device == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].keys["Description"] == "[REG_SZ] Intel(R) PRO/1000 MT Desktop Adapter"
    assert high_timeline.events[0].keys["ServiceName"] == "[REG_SZ] {9F272040-23C5-42CB-BBB3-EBCA31FB81C8}"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\config\SOFTWARE"
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
        'after': [],
    }

    assert high_timeline.events[0].trigger.id == 1
    assert high_timeline.events[0].trigger.description == r"Registry entry modification event found in 2024-04-17T01:16:00.609890+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards\2] Description: [REG_SZ] Intel(R) PRO/1000 MT Desktop Adapter ServiceName: [REG_SZ] {9F272040-23C5-42CB-BBB3-EBCA31FB81C8},winreg/winreg_default,NTFS:\Windows\System32\config\SOFTWARE,-"