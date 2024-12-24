import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.LastExecutedBAM import FindLastExecutedBAM


@pytest.fixture
def low_timeline():
    # create a test event to match against

    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-08-29T09:06:01.232572+00:00"
    event1.date_time_max = None
    event1.type = "Last Time Executed-REG"
    event1.path = r"NTFS:\Windows\System32\config\SYSTEM"
    event1.evidence = r"\Device\HarddiskVolume4\Windows\explorer.exe [S-1-5-21-3206686254-308435427-1198852649-1000]"
    event1.plugin = "REG-Background Activity Moderator Registry Key-winreg/bam"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T09:06:01.232572+00:00",
                      "Last Time Executed",
                      "REG",
                      "Background Activity Moderator Registry Key",
                      r"\Device\HarddiskVolume4\Windows\explorer.exe [S-1-5-21-3206686254-308435427-1198852649-1000]",
                      "winreg/bam",
                      r"NTFS:\Windows\System32\config\SYSTEM",
                      "-"]
    }
    event1.keys = None

    # Test for possible events that fits the initial low level event "description" regex
    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2024-08-29T10:00:19.339633+00:00"
    event2.date_time_max = None
    event2.type = "Last Time Executed-REG"
    event2.path = r"TESTPATH"
    event2.evidence = r"[\Objects\{b2721d73-1db4-4c62-bf78-c548a880142d}\Elements\14000006] Element: [REG_MULTI_SZ] [{7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}]"
    event2.plugin = "REG-WinFAKE-FAKE"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2024-08-29T10:00:19.339633+00:00",
                      "Last Time Executed",
                      "REG",
                      "WinFAKE",
                      r"[\Objects\{b2721d73-1db4-4c62-bf78-c548a880142d}\Elements\14000006] Element: [REG_MULTI_SZ] [{7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}]",
                      "FAKE",
                      r"NTFS:FAKE",
                      "-"]
    }
    event2.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    return timeline

def test_FindLastExecutedBAM(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindLastExecutedBAM(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Last Time Executed (Registry BAM)"
    assert high_timeline.events[0].description == "Last Time Executed of 'explorer.exe' by user id 'S-1-5-21-3206686254-308435427-1198852649-1000'"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "REG-Background Activity Moderator Registry Key-winreg/bam"
    assert high_timeline.events[0].keys["Path"] == "\Device\HarddiskVolume4\Windows\explorer.exe"
    assert high_timeline.events[0].keys["User ID"] == "S-1-5-21-3206686254-308435427-1198852649-1000"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\config\SYSTEM"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Last Time Executed of '\Device\HarddiskVolume4\Windows\explorer.exe' found in 'NTFS:\Windows\System32\config\SYSTEM' by Background Activity Monitor",
        'test_event': {
            'type': "Last Time Executed-REG",
            'evidence': r'\[\S+\]$'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://docs.velociraptor.app/docs/forensic/evidence_of_execution/',
        'keys': {},
    }




