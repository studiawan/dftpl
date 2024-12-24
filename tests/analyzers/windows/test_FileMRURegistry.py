import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.FileMRURegistry import FindFileMRURegistry


@pytest.fixture
def low_timeline():
    # create a test event to match against

    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-12-15T00:05:55.561672+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Users\User\NTUSER.DAT"
    event1.evidence = r"[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\User MRU\LiveId_AAAAAAAAAAAAAAAAAAAAAAAAA\File MRU] FOLDERID_Desktop: [REG_SZ] C:\Users\User\Desktop\ FOLDERID_Documents: [REG_SZ] C:\Users\User\Documents\ Item 1: [REG_SZ] [F00000000][T01DB4E851CA27F70][O00000000]*D:\Documents\2024v2.xlsx Item 2: [REG_SZ] [F00000000][T01DB1B07BC3543D0][O00000000]*D:\Documents\timeline.csv Item 3: [REG_SZ] [F00000000][T01DB18C55A137490][O00000000]*D:\Documents\TM06.csv Item 4: [REG_SZ] [F00000000][T01DADFCDC675A760][O00000000]*C:\Users\User\Documents\timeline-experiments\timelinecsv.csv"
    event1.plugin = "REG-Registry Key-winreg/winreg_default"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-12-15T00:05:55.561672+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\User MRU\LiveId_AAAAAAAAAAAAAAAAAAAAAAAAA\File MRU] FOLDERID_Desktop: [REG_SZ] C:\Users\User\Desktop\ FOLDERID_Documents: [REG_SZ] C:\Users\User\Documents\ Item 1: [REG_SZ] [F00000000][T01DB4E851CA27F70][O00000000]*D:\Documents\2024v2.xlsx Item 2: [REG_SZ] [F00000000][T01DB1B07BC3543D0][O00000000]*D:\Documents\timeline.csv Item 3: [REG_SZ] [F00000000][T01DB18C55A137490][O00000000]*D:\Documents\TM06.csv Item 4: [REG_SZ] [F00000000][T01DADFCDC675A760][O00000000]*C:\Users\User\Documents\timeline-experiments\timelinecsv.csv"
                      "winreg/winreg_default",
                      r"NTFS:\Users\User\NTUSER.DAT",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindFileMRURegistry(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindFileMRURegistry(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Office File MRU Registry Key"
    assert high_timeline.events[0].description == "Update time for most recently used documents for logged in microsoft user of 'Excel' 16.0 with 4 entries"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].plugin == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].keys["Key Path"] == r"HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\User MRU\LiveId_AAAAAAAAAAAAAAAAAAAAAAAAA\File MRU"
    assert high_timeline.events[0].keys["Office Version"] == "16.0"
    assert high_timeline.events[0].keys["Office Application"] == "Excel"
    assert high_timeline.events[0].keys["FOLDERID_Desktop"] == "C:\\Users\\User\Desktop\\"
    assert high_timeline.events[0].keys["FOLDERID_Documents"] == "C:\\Users\\User\Documents\\"
    assert high_timeline.events[0].keys["Item 1 Name"] == r"D:\Documents\2024v2.xlsx"
    assert high_timeline.events[0].keys["Item 1 Timestamp"] == "2024-12-15T00:05:55.559000+00:00"
    assert high_timeline.events[0].keys["Item 2 Name"] == r"D:\Documents\timeline.csv"
    assert high_timeline.events[0].keys["Item 2 Timestamp"] == "2024-10-10T11:29:57.389000+00:00"
    assert high_timeline.events[0].keys["Item 3 Name"] == "D:\Documents\TM06.csv"
    assert high_timeline.events[0].keys["Item 3 Timestamp"] == "2024-10-07T14:29:43.641000+00:00"
    assert high_timeline.events[0].keys["Item 4 Name"] == r"C:\Users\User\Documents\timeline-experiments\timelinecsv.csv"
    assert high_timeline.events[0].keys["Item 4 Timestamp"] == "2024-07-27T02:36:25.174000+00:00"
    assert high_timeline.events[0].files == r"NTFS:\Users\User\NTUSER.DAT"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Update time for 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\User MRU\LiveId_AAAAAAAAAAAAAAAAAAAAAAAAA\File MRU' registry key with 4 entries found in 'NTFS:\Users\User\NTUSER.DAT'",
        'test_event': {
            'type': "Content Modification Time-REG",
            'evidence': r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\S*?\\'
                           r'(?:PowerPoint|Excel|Word)\\(?:File MRU|User MRU\\LiveId_.+?\\File MRU)\]'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://www.cybertriage.com/artifact/office-mru-registry/',
        'keys': {},
    }




