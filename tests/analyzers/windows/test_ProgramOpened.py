import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.ProgramOpened import ProgramOpened

# file explorer is opened
# 2023-12-26 00:37:46.738362+00:00,Last Access Time,FILE,File stat,NTFS:\Windows\explorer.exe Type: file,filestat,NTFS:\Windows\explorer.exe,-

# cmd.exe is opened
# 2023-12-26 00:36:59.234628+00:00,Last Access Time,FILE,File stat,NTFS:\Windows\System32\cmd.exe Type: file,filestat,NTFS:\Windows\System32\cmd.exe,-

@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:37:46.738362+00:00"
    event1.date_time_max = None
    event1.type = "Last Access Time-FILE"
    event1.path = r"NTFS:\Windows\explorer.exe"
    event1.evidence = r"NTFS:\Windows\explorer.exe Type: file"
    event1.plugin = "FILE-File stat-filestat"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:37:46.738362+00:00",
                      "Last Access Time",
                      "FILE",
                      "File stat",
                      r"NTFS:\Windows\explorer.exe Type: file",
                      "filestat",
                      r"NTFS:\Windows\explorer.exe",
                      "-"]
    }
    event1.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26 00:36:59.234628+00:00"
    event2.date_time_max = None
    event2.type = "Last Access Time-FILE"
    event2.path = r"NTFS:\Windows\System32\cmd.exe"
    event2.evidence = r"NTFS:\Windows\System32\cmd.exe Type: file"
    event2.plugin = "FILE-File stat-filestat"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2023-12-26 00:36:59.234628+00:00",
                      "Last Access Time",
                      "FILE",
                      "File stat",
                      r"NTFS:\Windows\System32\cmd.exe Type: file",
                      "filestat",
                      r"NTFS:\Windows\System32\cmd.exe",
                      "-"]
    }
    event2.keys = None
    timeline.add_event(event2)

    return timeline

def test_ProgramOpened(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = ProgramOpened(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].id == 1
    assert high_timeline.events[0].date_time_min == "2023-12-26 00:37:46.738362+00:00"
    assert high_timeline.events[0].date_time_max == "2023-12-26 00:37:46.738362+00:00"
    assert high_timeline.events[0].evidence_source == r"NTFS:\Windows\explorer.exe Type: file"
    assert high_timeline.events[0].type == "Program opened"
    assert high_timeline.events[0].description == "A Windows program explorer.exe was opened"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].plugin == "FILE-File stat-filestat"
    assert high_timeline.events[0].files == r"NTFS:\Windows\explorer.exe"
    assert high_timeline.events[0].supporting == {
        'before': [],
        'after': [
            {
                'id': 2,
                'date_time_min': "2023-12-26 00:36:59.234628+00:00",
                'date_time_max': None,
                'type': "Last Access Time-FILE",
                'path': r"NTFS:\Windows\System32\cmd.exe",
                'evidence': r"NTFS:\Windows\System32\cmd.exe Type: file",
                'plugin': "FILE-File stat-filestat",
                'provenance': {
                    'line_number': 2,
                    'raw_entry': ["2023-12-26 00:36:59.234628+00:00",
                                  "Last Access Time",
                                  "FILE",
                                  "File stat",
                                  r"NTFS:\Windows\System32\cmd.exe Type: file",
                                  "filestat",
                                  r"NTFS:\Windows\System32\cmd.exe",
                                  "-"]
                },
                'keys': None
            }
        ],
    }