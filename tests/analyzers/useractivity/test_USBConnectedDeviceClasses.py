import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.USBConnectedRegDeviceClasses import FindUSBConnectedDeviceClasses

@pytest.fixture
def low_timeline():
    # DeviceClasses
    event = LowLevelEvent()
    event.id = 1
    event.date_time_min = "2024-08-29T07:58:04.467136+00:00"
    event.date_time_max = None
    event.type = "Content Modification Time-REG"
    event.path = r"NTFS:\Windows\System32\config\SYSTEM"
    event.evidence = "[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\##?#USB#VID_1532&PID_0098#5&12c8f4c0&0&2#{a5dcbf10-6530-11d2-901f-00c04fb951ed}\#] (empty)"
    event.plugin = "REG-Registry Key-winreg/winreg_default"
    event.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T07:58:04.467136+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      "[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\##?#USB#VID_1532&PID_0098#5&12c8f4c0&0&2#{a5dcbf10-6530-11d2-901f-00c04fb951ed}\#] (empty)",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SYSTEM",
                      "-"]
    }
    event.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event)

    return timeline
def test_USBConnectedDeviceClasses(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindUSBConnectedDeviceClasses(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "USB Device Connected (Winreg DeviceClasses)"
    assert high_timeline.events[0].description == "USB device connected with Vendor ID '1532' and Product ID '0098' (Winreg DeviceClasses)."
    assert high_timeline.events[0].category == "User Activity"
    assert high_timeline.events[0].plugin == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].keys["ControlSet"] == "ControlSet001"
    assert high_timeline.events[0].keys["VID"] == "1532"
    assert high_timeline.events[0].keys["PID"] == "0098"
    assert high_timeline.events[0].keys["Serial"] == "5&12c8f4c0&0&2"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\config\SYSTEM"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"USB device connected with VID '1532' and PID '0098' in 'HKEY_LOCAL_MACHINE\System\ControlSet001\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\'.",
        'test_event': {
            'type': low_timeline.events[0].type,
                'evidence': r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00\d\\Control\\DeviceClasses\\{a5dcbf10-6530-11d2-901f-00c04fb951ed}\\[^\\]+\\#"
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://doi.org/10.1016/j.diin.2019.02.004',
        'keys': {},
    }