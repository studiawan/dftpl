import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.RunRunOnceRegistry import FindRunRunOnceRegistry


@pytest.fixture
def low_timeline():

    # Test for events without entries
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-04-16T20:18:43.574367+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-REG"
    event1.path = r"NTFS:\Windows\System32\config\SOFTWARE"
    event1.evidence = r"[HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce] Entries: []"
    event1.plugin = "REG-Run/Run Once Registry Key-winreg/windows_run"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-04-16T20:18:43.574367+00:00",
                      "Content Modification Time",
                      "REG",
                      "Run/Run Once Registry Key",
                      "[HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce] Entries: []"
                      "winreg/windows_run",
                      r"NTFS:\Windows\System32\config\SOFTWARE",
                      "-"]
    }
    event1.keys = None

    # Test for events with entries
    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2024-08-29T07:59:39.896420+00:00"
    event2.date_time_max = None
    event2.type = "Content Modification Time-REG"
    event2.path = r"NTFS:\Users\User\NTUSER.DAT"
    event2.evidence = r"""[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run] Entries: ['MicrosoftEdgeAutoLaunch_C46CFC0629905CC775E70B50EA8A519C: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --no-startup-window --win-session-start'  'OneDrive: "C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background']"""
    event2.plugin = "REG-Run/Run Once Registry Key-winreg/windows_run"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2024-08-29T07:59:39.896420+00:00",
                      "Content Modification Time",
                      "REG",
                      "Run/Run Once Registry Key",
                      r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run] Entries: ['MicrosoftEdgeAutoLaunch_C46CFC0629905CC775E70B50EA8A519C: \"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start'  'OneDrive: \"C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background']",
                      "winreg/windows_run",
                      r"NTFS:\Users\User\NTUSER.DAT",
                      "-"]
    }
    event2.keys = None


    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)


    return timeline

def test_FindRunRunOnceRegistry(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindRunRunOnceRegistry(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].type == "Run/Run Once Registry Key"
    assert high_timeline.events[0].description == "Update time for list of programs run when user logon 'HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' registry key with 0 entries"
    assert high_timeline.events[0].category == "System"
    assert high_timeline.events[0].plugin == "REG-Run/Run Once Registry Key-winreg/windows_run"
    assert high_timeline.events[0].keys["Key Path"] == "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    assert high_timeline.events[0].keys["Program1 Name"] == "None"
    assert high_timeline.events[0].keys["Program1 Path"] == "None"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\config\SOFTWARE"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"Update time for 'HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' registry key with 0 entries found in 'NTFS:\Windows\System32\config\SOFTWARE'",
        'test_event': {
            'type': low_timeline.events[1].type,
            'evidence': r'^\[(?:HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software\\(?:WOW6432Node\\)?'
                           r'Microsoft\\Windows\\CurrentVersion\\'
                           r'(?:Run|RunOnce|RunOnce\\Setup|RunServices|RunServicesOnce)\]'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://attack.mitre.org/techniques/T1547/001/',
        'keys': {},
    }


    assert high_timeline.events[1].type == "Run/Run Once Registry Key"
    assert high_timeline.events[1].description == "Update time for list of programs run when user logon 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run' registry key with 2 entries"
    assert high_timeline.events[1].category == "System"
    assert high_timeline.events[1].plugin == "REG-Run/Run Once Registry Key-winreg/windows_run"
    assert high_timeline.events[1].keys["Key Path"] == "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
    assert high_timeline.events[1].keys["Program1 Name"] == "MicrosoftEdgeAutoLaunch_C46CFC0629905CC775E70B50EA8A519C"
    assert high_timeline.events[1].keys["Program1 Path"] == r'"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --no-startup-window --win-session-start'
    assert high_timeline.events[1].keys["Program2 Name"] == "OneDrive"
    assert high_timeline.events[1].keys["Program2 Path"] == r'"C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background'
    assert high_timeline.events[1].files == r"NTFS:\Users\User\NTUSER.DAT"

    assert high_timeline.events[1].trigger == {
        'id': low_timeline.events[1].id,
        'description': r"Update time for 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run' registry key with 2 entries found in 'NTFS:\Users\User\NTUSER.DAT'",
        'test_event': {
            'type': low_timeline.events[1].type,
            'evidence': r'^\[(?:HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software\\(?:WOW6432Node\\)?'
                           r'Microsoft\\Windows\\CurrentVersion\\'
                           r'(?:Run|RunOnce|RunOnce\\Setup|RunServices|RunServicesOnce)\]'
        },
        'provenance': low_timeline.events[1].provenance,
        'references': 'https://attack.mitre.org/techniques/T1547/001/',
        'keys': {},
    }




