import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.LastExecutedUserAssist import FindLastExecutedUserAssist


@pytest.fixture
def low_timeline():
    # create a test event to match against

    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-08-29T07:59:34.847000+00:00"
    event1.date_time_max = None
    event1.type = "Last Time Executed-REG"
    event1.path = r"NTFS:\Users\User\NTUSER.DAT"
    event1.evidence = r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count] UserAssist entry: 15 Value name: MSEdge Count: 1 Application focus count: 6 Application focus duration: 946607"
    event1.plugin = "REG-UserAssist Registry Key-winreg/userassist"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T07:59:34.847000+00:00",
                      "Last Time Executed",
                      "REG",
                      "UserAssist Registry Key",
                      r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count] UserAssist entry: 15 Value name: MSEdge Count: 1 Application focus count: 6 Application focus duration: 946607",
                      "winreg/userassist",
                      r"NTFS:\Users\User\NTUSER.DAT",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindLastExecutedUserAssist(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindLastExecutedUserAssist(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Last Time Executed (Registry UserAssist)"
    assert high_timeline.events[0].description == "Last Time Executed of 'MSEdge' with 1 execution count"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "REG-UserAssist Registry Key-winreg/userassist"
    assert high_timeline.events[0].keys["UserAssist Entry"] == "15"
    assert high_timeline.events[0].keys["Value Name"] == "MSEdge"
    assert high_timeline.events[0].keys["Execution Count"] == "1"
    assert high_timeline.events[0].keys["Focus Count"] == "6"
    assert high_timeline.events[0].keys["Focus Duration"] == "946607"
    assert high_timeline.events[0].keys["Registry Path"] == r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
    assert high_timeline.events[0].files == r"NTFS:\Users\User\NTUSER.DAT"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Last Time Executed of 'MSEdge' found at 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count' in 'NTFS:\Users\User\NTUSER.DAT'",
        'test_event': {
            'type': "Last Time Executed-REG",
            'evidence': r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\\{\S*\}\\Count'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://www.magnetforensics.com/blog/artifact-profile-userassist/',
        'keys': {},
    }




