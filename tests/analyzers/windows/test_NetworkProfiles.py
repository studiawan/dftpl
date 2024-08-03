import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.NetworkProfiles import FindNetworkProfiles


@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-07-12T05:50:14.347797+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Windows\System32\config\SOFTWARE"
    event1.evidence = r"[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{400F2E8B-9AB8-4DA6-8705-455176209E17}] Category: [REG_DWORD_LE] 0 DateCreated: [REG_BINARY] (16 bytes) DateLastConnected: [REG_BINARY] (16 bytes) Description: [REG_SZ] Network Managed: [REG_DWORD_LE] 0 NameType: [REG_DWORD_LE] 6 ProfileName: [REG_SZ] Network"
    event1.plugin = "REG-Registry Key-winreg/winreg_default"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-07-12T05:50:14.347797+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{400F2E8B-9AB8-4DA6-8705-455176209E17}] Category: [REG_DWORD_LE] 0 DateCreated: [REG_BINARY] (16 bytes) DateLastConnected: [REG_BINARY] (16 bytes) Description: [REG_SZ] Network Managed: [REG_DWORD_LE] 0 NameType: [REG_DWORD_LE] 6 ProfileName: [REG_SZ] Network",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SOFTWARE",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindNetworkProfiles(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindNetworkProfiles(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Network Connection"
    assert high_timeline.events[0].description == "Network Profile 'Network' possibly in use"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].device == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].keys["Category"] == "[REG_DWORD_LE] 0"
    assert high_timeline.events[0].keys["DateCreated"] == "[REG_BINARY] (16 bytes)"
    assert high_timeline.events[0].keys["DateLastConnected"] == "[REG_BINARY] (16 bytes)"
    assert high_timeline.events[0].keys["Description"] == "[REG_SZ] Network"
    assert high_timeline.events[0].keys["Managed"] == "[REG_DWORD_LE] 0"
    assert high_timeline.events[0].keys["NameType"] == "[REG_DWORD_LE] 6"
    assert high_timeline.events[0].keys["ProfileName"] == "[REG_SZ] Network"
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
    assert high_timeline.events[0].trigger.description == r"Registry entry for network profile found in 2024-07-12T05:50:14.347797+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{400F2E8B-9AB8-4DA6-8705-455176209E17}] Category: [REG_DWORD_LE] 0 DateCreated: [REG_BINARY] (16 bytes) DateLastConnected: [REG_BINARY] (16 bytes) Description: [REG_SZ] Network Managed: [REG_DWORD_LE] 0 NameType: [REG_DWORD_LE] 6 ProfileName: [REG_SZ] Network,winreg/winreg_default,NTFS:\Windows\System32\config\SOFTWARE,-"