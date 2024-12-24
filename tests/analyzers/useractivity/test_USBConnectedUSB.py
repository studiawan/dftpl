import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.USBConnectedUSB import FindUSBConnectedUSB

@pytest.fixture
def low_timeline():
    # Create 3 test event for windows registry modification artifacts
    # USB
    event = LowLevelEvent()
    event.id = 1
    event.date_time_min = "2024-08-29T07:57:24.603365+00:00"
    event.date_time_max = None
    event.type = "Last Connection Time-REG"
    event.path = r"NTFS:\Windows\System32\config\SYSTEM"
    event.evidence = r"[HKEY_LOCAL_MACHINE\System\ControlSet001\Enum\USB] Product: PID_1234 Serial: 5&12c8f4c0&0&2 Subkey name: VID_ABCD&PID_1234 Vendor: VID_ABCD"
    event.plugin = "REG-USB Registry Key-winreg/windows_usb_devices"
    event.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T07:57:24.603365+00:00",
                      "Last Connection Time",
                      "REG",
                      "USB Registry Key",
                      r"[HKEY_LOCAL_MACHINE\System\ControlSet001\Enum\USB] Product: PID_1234 Serial: 5&12c8f4c0&0&2 Subkey name: VID_ABCD&PID_1234 Vendor: VID_ABCD",
                      "winreg/windows_usb_devices",
                      r"NTFS:\Windows\System32\config\SYSTEM",
                      "-"]
    }
    event.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event)

    return timeline

def test_USBConnectedRegUSB(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindUSBConnectedUSB(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "USB Device Connected (Winreg USB)"
    assert high_timeline.events[0].description == "USB device connected with Vendor ID 'ABCD' and Product ID '1234' (Winreg USB)."
    assert high_timeline.events[0].category == "User Activity"
    assert high_timeline.events[0].plugin == "REG-USB Registry Key-winreg/windows_usb_devices"
    assert high_timeline.events[0].keys["ControlSet"] == "ControlSet001"
    assert high_timeline.events[0].keys["VID"] == "ABCD"
    assert high_timeline.events[0].keys["PID"] == "1234"
    assert high_timeline.events[0].keys["Subkey name"] == "VID_ABCD&PID_1234"
    assert high_timeline.events[0].keys["Serial"] == "5&12c8f4c0&0&2"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\config\SYSTEM"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"USB device connected with VID 'ABCD' and PID '1234' in 'HKEY_LOCAL_MACHINE\System\ControlSet001\Enum\USB'.",
        'test_event': {
            'type': low_timeline.events[0].type,
                'evidence': r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00\d\\Enum\\USB] Product: PID_"
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://doi.org/10.1016/j.diin.2019.02.004',
        'keys': {},
    }
