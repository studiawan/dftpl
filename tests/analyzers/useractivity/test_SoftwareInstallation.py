import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.SoftwareInstallation import FindFirefoxInstallation

# grep firefox 10.csv| head -n 40
# firefox installation
# registry
# 2023-12-26 00:41:49.590683+00:00,Content Modification Time,REG,Registry Key,[\Root\InventoryApplicationFile\setup-stub.exe|dd66fc2561b2d795] BinFileVersion: [REG_SZ] 1.0.0.0 BinProductVersion: [REG_SZ] 1.0.0.0 BinaryType: [REG_SZ] pe32_i386 FileId: [REG_SZ] 0000676eb262d5af80ffaef21b84e2b708b8bed788b0 Language: [REG_DWORD_LE] 1033 LinkDate: [REG_SZ] 07/24/2021 22:21:04 LowerCaseLongPath: [REG_SZ] c:\users\user\appdata\local\temp\7zsc2993177\setup-stub.exe Name: [REG_SZ] setup-stub.exe OriginalFileName: [REG_SZ] setup-stub.exe ProductName: [REG_SZ] firefox ProductVersion: [REG_SZ] 121.0 ProgramId: [REG_SZ] 00062aee3bf5b031d985321dd0a4ca99818f00000904 Publisher: [REG_SZ] mozilla corporation Size: [REG_QWORD] 563792 Usn: [REG_QWORD] 273229640 Version: [REG_SZ] 121.0,winreg/amcache,NTFS:\Windows\appcompat\Programs\Amcache.hve,-

# folder creation
# 2023-12-26 00:42:53.931866+00:00,Creation Time,FILE,File stat,NTFS:\Program Files\Mozilla Firefox\firefox.exe Type: file,filestat,NTFS:\Program Files\Mozilla Firefox\firefox.exe,-

# windows shortcut creation
# 2023-12-26 00:42:53.931866+00:00,Creation Time,LNK,Windows Shortcut,File size: 674720 File attribute flags: 0x00000020 Drive type: 3 Drive serial number: 0x5ce1df5a Volume label: Windows Local path: C:\Program Files\Mozilla Firefox\firefox.exe Relative path: ..\..\..\..\..\Program Files\Mozilla Firefox\firefox.exe Working dir: C:\Program Files\Mozilla Firefox Link target: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe,lnk,NTFS:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox.lnk,-

# start menu
# 2023-12-26 00:42:54+00:00,Creation Time,FILE,File entry shell item,Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: Firefox.lnk,lnk/shell_items,NTFS:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox.lnk,-

# desktop
# 2023-12-26 00:42:54+00:00,Creation Time,FILE,File entry shell item,Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: Firefox.lnk,lnk/shell_items,NTFS:\Users\Public\Desktop\Firefox.lnk,-

@pytest.fixture
def low_timeline():
    # Create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:41:49.590683+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Windows\appcompat\Programs\Amcache.hve"
    event1.evidence = r"[\Root\InventoryApplicationFile\setup-stub.exe|dd66fc2561b2d795] BinFileVersion: [REG_SZ] 1.0.0.0 BinProductVersion: [REG_SZ] 1.0.0.0 BinaryType: [REG_SZ] pe32_i386 FileId: [REG_SZ] 0000676eb262d5af80ffaef21b84e2b708b8bed788b0 Language: [REG_DWORD_LE] 1033 LinkDate: [REG_SZ] 07/24/2021 22:21:04 LowerCaseLongPath: [REG_SZ] c:\users\user\appdata\local\temp\7zsc2993177\setup-stub.exe Name: [REG_SZ] setup-stub.exe OriginalFileName: [REG_SZ] setup-stub.exe ProductName: [REG_SZ] firefox ProductVersion: [REG_SZ] 121.0 ProgramId: [REG_SZ] 00062aee3bf5b031d985321dd0a4ca99818f00000904 Publisher: [REG_SZ] mozilla corporation Size: [REG_QWORD] 563792 Usn: [REG_QWORD] 273229640 Version: [REG_SZ] 121.0"
    event1.plugin = "REG-Registry Key-winreg/amcache"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:41:49.590683+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[\Root\InventoryApplicationFile\setup-stub.exe|dd66fc2561b2d795] BinFileVersion: [REG_SZ] 1.0.0.0 BinProductVersion: [REG_SZ] 1.0.0.0 BinaryType: [REG_SZ] pe32_i386 FileId: [REG_SZ] 0000676eb262d5af80ffaef21b84e2b708b8bed788b0 Language: [REG_DWORD_LE] 1033 LinkDate: [REG_SZ] 07/24/2021 22:21:04 LowerCaseLongPath: [REG_SZ] c:\users\user\appdata\local\temp\7zsc2993177\setup-stub.exe Name: [REG_SZ] setup-stub.exe OriginalFileName: [REG_SZ] setup-stub.exe ProductName: [REG_SZ] firefox ProductVersion: [REG_SZ] 121.0 ProgramId: [REG_SZ] 00062aee3bf5b031d985321dd0a4ca99818f00000904 Publisher: [REG_SZ] mozilla corporation Size: [REG_QWORD] 563792 Usn: [REG_QWORD] 273229640 Version: [REG_SZ] 121.0",
                      "winreg/amcache",
                      r"NTFS:\Windows\appcompat\Programs\Amcache.hve",
                      "-"]
    }
    event1.keys = None

    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26 00:42:53.931866+00:00"
    event2.date_time_max = None
    event2.type = "Creation Time-FILE"
    event2.path = r"NTFS:\Program Files\Mozilla Firefox\firefox.exe"
    event2.evidence = r"NTFS:\Program Files\Mozilla Firefox\firefox.exe Type: file"
    event2.plugin = "FILE-File stat-filestat"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2023-12-26 00:42:53.931866+00:00",
                      "Creation Time",
                      "FILE",
                      "File stat",
                      r"NTFS:\Program Files\Mozilla Firefox\firefox.exe Type: file",
                      "filestat",
                      r"NTFS:\Program Files\Mozilla Firefox\firefox.exe",
                      "-"]
    }
    event2.keys = None

    event3 = LowLevelEvent()
    event3.id = 3
    event3.date_time_min = "2023-12-26 00:42:53.931866+00:00"
    event3.date_time_max = None
    event3.type = "Creation Time-LNK"
    event3.path = r"NTFS:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox.lnk"
    event3.evidence = r"File size: 674720 File attribute flags: 0x00000020 Drive type: 3 Drive serial number: 0x5ce1df5a Volume label: Windows Local path: C:\Program Files\Mozilla Firefox\firefox.exe Relative path: ..\..\..\..\..\Program Files\Mozilla Firefox\firefox.exe Working dir: C:\Program Files\Mozilla Firefox Link target: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe"
    event3.plugin = "LNK-Windows Shortcut-lnk"
    event3.provenance = {
        'line_number': 3,
        'raw_entry': ["2023-12-26 00:42:53.931866+00:00",
                      "Creation Time",
                      "LNK",
                      "Windows Shortcut",
                      r"File size: 674720 File attribute flags: 0x00000020 Drive type: 3 Drive serial number: 0x5ce1df5a Volume label: Windows Local path: C:\Program Files\Mozilla Firefox\firefox.exe Relative path: ..\..\..\..\..\Program Files\Mozilla Firefox\firefox.exe Working dir: C:\Program Files\Mozilla Firefox Link target: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe",
                      "lnk",
                      r"NTFS:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox.lnk",
                      "-"]
    }
    event3.keys = None

    event4 = LowLevelEvent()
    event4.id = 4
    event4.date_time_min = "2023-12-26 00:42:54+00:00"
    event4.date_time_max = None
    event4.type = "Creation Time-FILE"
    event4.path = r"NTFS:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox.lnk"
    event4.evidence = r"Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: Firefox.lnk"
    event4.plugin = "FILE-File entry shell item-lnk/shell_items"
    event4.provenance = {
        'line_number': 4,
        'raw_entry': ["2023-12-26 00:42:54+00:00",
                      "Creation Time",
                      "FILE",
                      "File entry shell item",
                      r"Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: Firefox.lnk",
                      "lnk/shell_items",
                      r"NTFS:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox.lnk",
                      "-"]
    }
    event4.keys = None

    event5 = LowLevelEvent()
    event5.id = 5
    event5.date_time_min = "2023-12-26 00:42:54+00:00"
    event5.date_time_max = None
    event5.type = "Creation Time-FILE"
    event5.path = r"NTFS:\Users\Public\Desktop\Firefox.lnk"
    event5.evidence = r"Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: Firefox.lnk"
    event5.plugin = "FILE-File entry shell item-lnk/shell_items"
    event5.provenance = {
        'line_number': 5,
        'raw_entry': ["2023-12-26 00:42:54+00:00",
                      "Creation Time",
                      "FILE",
                      "File entry shell item",
                      r"Name: firefox.exe Long name: firefox.exe NTFS file reference: 244435-3 Shell item path: <My Computer> C:\Program Files\Mozilla Firefox\firefox.exe Origin: Firefox.lnk",
                      "lnk/shell_items",
                      r"NTFS:\Users\Public\Desktop\Firefox.lnk",
                      "-"]
    }
    event5.keys = None

    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)
    timeline.add_event(event3)
    timeline.add_event(event4)
    timeline.add_event(event5)

    return timeline

def test_FindFirefoxInstallation(low_timeline):
    start_id = 0
    end_id = 6
    high_timeline = FindFirefoxInstallation(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 5
