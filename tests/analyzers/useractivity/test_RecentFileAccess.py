import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.RecentFileAccess import RecentFileAccess


# grep -i recent 7.csv | grep "Windows Shortcut"
# windows shortcut
# 2023-12-26 00:42:53.931866+00:00,Creation Time,LNK,Windows Shortcut,[Open a new browser tab.] File size: 674720 File attribute flags: 0x00000020 Drive type: 3 Drive serial number: 0x5ce1df5a Volume label: Windows Local path: C:\Program Files\Mozilla Firefox\firefox.exe cmd arguments: -new-tab about:blank Icon location: C:\Program Files\Mozilla Firefox\firefox.exe Link target: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe,custom_destinations/lnk,NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\40371339ad31a7e6.customDestinations-ms,-

# \Recent and lnk files
# grep -i recent 7.csv | grep "Last Access Time"
# 2023-12-26 00:43:12+00:00,Last Access Time,FILE,File entry shell item,Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: 6824f4a902c78fbd.customDestinations-ms,custom_destinations/lnk/shell_items,NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\6824f4a902c78fbd.customDestinations-ms,-


@pytest.fixture
def low_timeline():
    # Create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:42:53.931866+00:00"
    event1.date_time_max = None
    event1.type = "Creation Time-LNK"
    event1.path = r"NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\40371339ad31a7e6.customDestinations-ms"
    event1.evidence = r"[Open a new browser tab.] File size: 674720 File attribute flags: 0x00000020 Drive type: 3 Drive serial number: 0x5ce1df5a Volume label: Windows Local path: C:\Program Files\Mozilla Firefox\firefox.exe cmd arguments: -new-tab about:blank Icon location: C:\Program Files\Mozilla Firefox\firefox.exe Link target: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe"
    event1.plugin = "LNK-Windows Shortcut-custom_destinations/lnk"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:42:53.931866+00:00",
                      "Creation Time",
                      "LNK",
                      "Windows Shortcut",
                      r"[Open a new browser tab.] File size: 674720 File attribute flags: 0x00000020 Drive type: 3 Drive serial number: 0x5ce1df5a Volume label: Windows Local path: C:\Program Files\Mozilla Firefox\firefox.exe cmd arguments: -new-tab about:blank Icon location: C:\Program Files\Mozilla Firefox\firefox.exe Link target: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe",
                      "custom_destinations/lnk",
                      r"NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\40371339ad31a7e6.customDestinations-ms",
                      "-"]
    }
    event1.keys = None

    # Create a test event to match against
    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26 00:43:12+00:00"
    event2.date_time_max = None
    event2.type = "Last Access Time-FILE"
    event2.path = r"NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\6824f4a902c78fbd.customDestinations-ms"
    event2.evidence = r"Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: 6824f4a902c78fbd.customDestinations-ms"
    event2.plugin = "FILE-File entry shell item-custom_destinations/lnk/shell_items"
    event2.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:43:12+00:00",
                      "Last Access Time",
                      "FILE",
                      "File entry shell item",
                      r"Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: 6824f4a902c78fbd.customDestinations-ms",
                      "custom_destinations/lnk/shell_items",
                      r"NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\6824f4a902c78fbd.customDestinations-ms",
                      "-"]
    }
    event2.keys = None

    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    return timeline

def test_RecentFileAccess(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = RecentFileAccess(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].id == 1
    assert high_timeline.events[0].date_time_min == "2023-12-26 00:42:53.931866+00:00" 
    assert high_timeline.events[0].date_time_max == "2023-12-26 00:42:53.931866+00:00" 
    assert high_timeline.events[0].evidence_source == r"[Open a new browser tab.] File size: 674720 File attribute flags: 0x00000020 Drive type: 3 Drive serial number: 0x5ce1df5a Volume label: Windows Local path: C:\Program Files\Mozilla Firefox\firefox.exe cmd arguments: -new-tab about:blank Icon location: C:\Program Files\Mozilla Firefox\firefox.exe Link target: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe"
    assert high_timeline.events[0].type == "Recent File Access"
    assert high_timeline.events[0].description == "Recent File Access"
    assert high_timeline.events[0].category == "User Activity"
    assert high_timeline.events[0].device == "LNK-Windows Shortcut-custom_destinations/lnk"
    assert high_timeline.events[0].files == r"NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\40371339ad31a7e6.customDestinations-ms"
    assert high_timeline.events[0].keys['file_details_from_lnk'] == {
        'File size': '674720',
        'File attribute flags': '0x00000020',
        'Drive type': '3',
        'Drive serial number': '0x5ce1df5a',
        'Volume label': 'Windows',
        'Local path': 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
        'cmd arguments': '-new-tab about:blank',
        'Icon location': 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
        'Link target': '<My Computer> C:\\Program Files\\Mozilla Firefox\\firefox.exe'
    }

def test_RecentFileAccess2(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = RecentFileAccess(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[1].id == 2
    assert high_timeline.events[1].date_time_min == "2023-12-26 00:43:12+00:00" 
    assert high_timeline.events[1].date_time_max == "2023-12-26 00:43:12+00:00" 
    assert high_timeline.events[1].evidence_source == r"Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: 6824f4a902c78fbd.customDestinations-ms"
    assert high_timeline.events[1].type == "Recent File Access"
    assert high_timeline.events[1].description == "Recent File Access"
    assert high_timeline.events[1].category == "User Activity"
    assert high_timeline.events[1].device == "FILE-File entry shell item-custom_destinations/lnk/shell_items"
    assert high_timeline.events[1].files == r"NTFS:\Users\User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\6824f4a902c78fbd.customDestinations-ms"
    assert high_timeline.events[1].keys['file_details_from_entry_shell'] == {
        'Name': 'firefox.exe',
        'Long name': 'firefox.exe',
        'NTFS file reference': '244435-3',
        'Shell item path': '<My Computer> C:\\Program Files\\Mozilla Firefox\\firefox.exe',
        'Origin': '6824f4a902c78fbd.customDestinations-ms'
    }
