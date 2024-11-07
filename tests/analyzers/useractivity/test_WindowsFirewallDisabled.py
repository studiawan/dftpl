import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.WindowsFirewallDisabled import FindWindowsFirewallDisabled

@pytest.fixture
def low_timeline():
    # Create 2 test event for windows event log artifacts
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26T23:26:57.492844+00:00"
    event1.date_time_max = None
    event1.type = "Content Modification Time-EVT"
    event1.path = r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
    event1.evidence = "[2082 / 0x0822] Provider identifier: {d1bc9aff-2abf-4d71-9146-ecb2a986eb85} Source Name: Microsoft-Windows-Windows Firewall With Advanced Security Strings: ['2'  '1'  '4'  '00000000'  'No'  '1'  'S-1-5-21-4087375726-1105420669-2909453743-1000'  'C:\\Windows\\System32\\dllhost.exe'  '0'] Computer Name: WinDev2311Eval Record Number: 894 Event Level: 4"
    event1.plugin = "EVT-WinEVTX-winevtx"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26T23:26:57.492844+00:00",
                      "Content Modification Time",
                      "EVT",
                      "WinEVTX",
                      "[2082 / 0x0822] Provider identifier: {d1bc9aff-2abf-4d71-9146-ecb2a986eb85} Source Name: Microsoft-Windows-Windows Firewall With Advanced Security Strings: ['2'  '1'  '4'  '00000000'  'No'  '1'  'S-1-5-21-4087375726-1105420669-2909453743-1000'  'C:\\Windows\\System32\\dllhost.exe'  '0'] Computer Name: WinDev2311Eval Record Number: 894 Event Level: 4",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
                      "-"]
    }
    event1.keys = None

    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26T23:26:57.668246+00:00"
    event2.date_time_max = None
    event2.type = "Content Modification Time-EVT"
    event2.path = r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
    event2.evidence = "[2082 / 0x0822] Provider identifier: {d1bc9aff-2abf-4d71-9146-ecb2a986eb85} Source Name: Microsoft-Windows-Windows Firewall With Advanced Security Strings: ['4'  '1'  '4'  '00000000'  'No'  '1'  'S-1-5-21-4087375726-1105420669-2909453743-1000'  'C:\\Windows\\System32\\dllhost.exe'  '0'] Computer Name: WinDev2311Eval Record Number: 894 Event Level: 4"
    event2.plugin = "EVT-WinEVTX-winevtx"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2023-12-26T23:26:57.668246+00:00",
                      "Content Modification Time",
                      "EVT",
                      "WinEVTX",
                      "[2082 / 0x0822] Provider identifier: {d1bc9aff-2abf-4d71-9146-ecb2a986eb85} Source Name: Microsoft-Windows-Windows Firewall With Advanced Security Strings: ['4'  '1'  '4'  '00000000'  'No'  '1'  'S-1-5-21-4087375726-1105420669-2909453743-1000'  'C:\\Windows\\System32\\dllhost.exe'  '0'] Computer Name: WinDev2311Eval Record Number: 895 Event Level: 4",
                      "winevtx",
                      r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
                      "-"]
    }
    event2.keys = None

    # Create 2 test event for windows registry modification artifacts
    event3 = LowLevelEvent()
    event3.id = 3
    event3.date_time_min = "2023-12-26T23:26:57.473689+00:00"
    event3.date_time_max = None
    event3.type = "Content Modification Time-REG"
    event3.path = r"NTFS:\Windows\System32\config\SYSTEM"
    event3.evidence = "[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile] DisableNotifications: [REG_DWORD_LE] 0 EnableFirewall: [REG_DWORD_LE] 0"
    event3.plugin = "REG-Registry Key-winreg/winreg_default"
    event3.provenance = {
        'line_number': 3,
        'raw_entry': ["2023-12-26T23:26:57.473689+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      "[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile] DisableNotifications: [REG_DWORD_LE] 0 EnableFirewall: [REG_DWORD_LE] 0",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SYSTEM",
                      "-"]
    }
    event3.keys = None

    event4 = LowLevelEvent()
    event4.id = 4
    event4.date_time_min = "2023-12-26T23:26:57.509597+00:00"
    event4.date_time_max = None
    event4.type = "Content Modification Time-REG"
    event4.path = r"NTFS:\Windows\System32\config\SYSTEM"
    event4.evidence = "[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile] DisableNotifications: [REG_DWORD_LE] 0 EnableFirewall: [REG_DWORD_LE] 0"
    event4.plugin = "REG-Registry Key-winreg/winreg_default"
    event4.provenance = {
        'line_number': 4,
        'raw_entry': ["2023-12-26T23:26:57.509597+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      "[HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile] DisableNotifications: [REG_DWORD_LE] 0 EnableFirewall: [REG_DWORD_LE] 0",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SYSTEM",
                      "-"]
    }
    event4.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)
    timeline.add_event(event3)
    timeline.add_event(event4)

    return timeline

def test_WindowsFirewallDisabledWinEVT(low_timeline):
    start_id = 0
    end_id = 4
    high_timeline = FindWindowsFirewallDisabled(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 4
    assert high_timeline.events[0].type == "Windows Firewall Disabled"
    assert high_timeline.events[0].description == "Windows Firewall disabled for 'Private' profile (Windows Event Log)."
    assert high_timeline.events[0].category == "User Activity"
    assert high_timeline.events[0].plugin == "EVT-WinEVTX-winevtx"
    assert high_timeline.events[0].keys["Profiles"] == "2"
    assert high_timeline.events[0].keys["Origin"] == "1"
    assert high_timeline.events[0].keys["ModifyingUser"] == "S-1-5-21-4087375726-1105420669-2909453743-1000"
    assert high_timeline.events[0].keys["ModifyingApplication"] == "C:\\Windows\\System32\\dllhost.exe"
    assert high_timeline.events[0].keys["ErrorCode"] == "0"
    assert high_timeline.events[0].keys["ComputerName"] == "WinDev2311Eval"
    assert high_timeline.events[0].keys["RecordNumber"] == "894"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
    assert len(high_timeline.events[0].supporting['before']) == 0
    assert len(high_timeline.events[0].supporting['after']) == 3

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': "Windows Firewall disabled event found for 'Private' profile in 'NTFS:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx' with event id '2082'.",
        'test_event': {
            'type': low_timeline.events[0].type,
                'evidence': r"^\[2082.*?\].+Source Name: Microsoft-Windows-Windows Firewall With Advanced Security Strings: \['[124]'  '1'  '.+?'  '.+?'  'No'"
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://detection.fyi/sigmahq/sigma/windows/builtin/firewall_as/win_firewall_as_setting_change/',
        'keys': {},
    }


def test_WindowsFirewallDisabledWinReg(low_timeline):
    start_id = 0
    end_id = 4
    high_timeline = FindWindowsFirewallDisabled(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 4
    assert high_timeline.events[2].type == "Windows Firewall Disabled"
    assert high_timeline.events[2].description == "Windows Firewall disabled for 'Private' profile (Windows Registry)."
    assert high_timeline.events[2].category == "User Activity"
    assert high_timeline.events[2].plugin == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[2].keys["Profiles"] == "Private"
    assert high_timeline.events[2].keys["DisableNotifications"] == "0"
    assert high_timeline.events[2].keys["EnableFirewall"] == "0"
    assert high_timeline.events[2].files == "NTFS:\Windows\System32\config\SYSTEM"
    # TODO : Why is there only 1 'before' supporting artifact?
    assert len(high_timeline.events[2].supporting['before']) == 2
    assert len(high_timeline.events[2].supporting['after']) == 1

    assert high_timeline.events[2].trigger == {
        'id': low_timeline.events[2].id,
        'description': "Windows Firewall disabled event found for 'Private' profile from changes to 'HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' registry key.",
        'test_event': {
            'type': low_timeline.events[2].type,
            'evidence': r'Services\\SharedAccess\\Parameters\\FirewallPolicy\\(?:Standard|Public|Domain)Profile\]'
        },
        'provenance': low_timeline.events[2].provenance,
        'references': 'https://blogs.cisco.com/security/talos/opening-zxshell',
        'keys': {},
    }
