import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.Users import CreatedUser


@pytest.fixture
def low_timeline():
    # Create a test event for user account creation with folder creation
    event1 = LowLevelEvent()
    event1.id = 0
    event1.date_time_min = "2023-12-26 23:30:24.568036+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path =   r"NTFS:\Windows\System32\config\SAM"
    event1.evidence = "[HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty)"
    event1.plugin = "REG-Registry Key-winreg/winreg_default"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 23:30:24.568036+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      "[HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty)",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SAM",
                      "-"]
    }
    event1.keys = None

    # Folder creation event for above's user
    event2 = LowLevelEvent()
    event2.id = 1
    event2.date_time_min = "2023-12-26 23:33:59.195066+00:00"
    event2.date_time_max = None
    event2.type = "Creation Time-FILE"
    event2.path = r"NTFS:\Users\root"
    event2.evidence = "NTFS:\\Users\\root Type: directory"
    event2.plugin = "FILE-File stat-filestat"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2023-12-26 23:33:59.195066+00:00",
                      "Creation Time",
                      "FILE",
                      "File stat",
                      "NTFS:\\Users\\root Type: directory"
                      "filestat",
                      r"NTFS:\Users\root",
                      "-"]
    }
    event2.keys = None

    # Create a test event for user account creation without folder creation
    event3 = LowLevelEvent()
    event3.id = 2
    event3.date_time_min = "2023-12-26 23:40:47.392280+00:00"
    event3.date_time_max = None
    event3.type = "Content Modification Time-REG"
    event3.path =   r"NTFS:\Windows\System32\config\SAM"
    event3.evidence = "[HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\\Users\\Names\\nofolderuser] (default): [UNKNOWN] (empty)"
    event3.plugin = "REG-Registry Key-winreg/winreg_default"
    event3.provenance = {
        'line_number': 3,
        'raw_entry': ["2023-12-26 23:40:47.392280+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      "[HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\\Users\\Names\\nofolderuser] (default): [UNKNOWN] (empty)",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SAM",
                      "-"]
    }
    event3.keys = None
    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)
    timeline.add_event(event3)

    return timeline


def test_FindUserCreationAndUserFolderCreation(low_timeline):
    start_id = 0
    end_id = 3
    high_timeline = CreatedUser(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    # Assert for user creation with folder creation
    assert high_timeline.events[0].type == "User created"
    assert high_timeline.events[0].description == "User 'root' created"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].device == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].files == "NTFS:\Windows\System32\config\SAM"
    assert high_timeline.events[0].keys["Username"] == "root"
    assert high_timeline.events[0].supporting['after'][0] == high_timeline.events[0].supporting['after'][2]
    # Assert for user creation without folder creation
    assert high_timeline.events[1].type == "User created"
    assert high_timeline.events[1].description == "User 'nofolderuser' created"
    assert high_timeline.events[1].category == "Windows"
    assert high_timeline.events[1].device == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[1].files == "NTFS:\Windows\System32\config\SAM"
    assert high_timeline.events[1].keys["Username"] == "nofolderuser"
    assert len(high_timeline.events[1].supporting['after']) <= 0