import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.windows.DeviceInstallation import FindDeviceInstallation

@pytest.fixture
def low_timeline():
    # create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2024-08-29T07:56:20.548000+00:00"
    event1.date_time_max = None
    event1.type = "Added Time-LOG"
    event1.path = r"NTFS:\Windows\INF\setupapi.dev.log"
    event1.evidence = "Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b} - SUCCESS"
    event1.plugin = "LOG-Setup API Log-text/setupapi"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T07:56:20.548000+00:00",
                      "Added Time",
                      "LOG",
                      "Setup API Log",
                      "Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b} - SUCCESS",
                      "text/setupapi",
                      r"NTFS:\Windows\INF\setupapi.dev.log",
                      "-"]
    }
    event1.keys = None

    # Create a test event to match against
    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2024-08-29T07:56:22.111000+00:00"
    event2.date_time_max = None
    event2.type = "End Time-LOG"
    event2.path = r"NTFS:\Windows\INF\setupapi.dev.log"
    event2.evidence = r"Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b} - SUCCESS"
    event2.plugin = "LOG-Setup API Log-text/setupapi"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2024-08-29T07:56:22.111000+00:00",
                      "End Time",
                      "LOG",
                      "Setup API Log",
                      "Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b} - SUCCESS",
                      "text/setupapi",
                      r"NTFS:\Windows\INF\setupapi.dev.log",
                      "-"]
    }
    event2.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    return timeline

def test_DeviceInstallationStart(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindDeviceInstallation(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[0].type == "Device Installation"
    assert high_timeline.events[0].description == "Start of installation with device instance ID 'SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'"
    assert high_timeline.events[0].category == "Windows"
    assert high_timeline.events[0].plugin == "LOG-Setup API Log-text/setupapi"
    assert high_timeline.events[0].keys["Title Description"] == "Hardware initiated"
    assert high_timeline.events[0].keys["Device Instance ID"] == "SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
    assert high_timeline.events[0].keys["Status Value"] == "SUCCESS"
    assert high_timeline.events[0].files == r"NTFS:\Windows\INF\setupapi.dev.log"
    assert len(high_timeline.events[0].supporting['before']) == 0
    assert len(high_timeline.events[0].supporting['after']) == 1

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': "Start of installation with device instance ID 'SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'",
        'test_event': {
            'type': low_timeline.events[0].type,
            'evidence': r'Device Install \(.+\) - .+ -'
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/format-of-a-text-log-section',
        'keys': {},
    }


def test_DeviceInstallationEnd(low_timeline):
    start_id = 0
    end_id = 2
    high_timeline = FindDeviceInstallation(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 2
    assert high_timeline.events[1].type == "Device Installation"
    assert high_timeline.events[1].description == "End of installation with device instance ID 'SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'"
    assert high_timeline.events[1].category == "Windows"
    assert high_timeline.events[1].plugin == "LOG-Setup API Log-text/setupapi"
    assert high_timeline.events[1].keys["Title Description"] == "Hardware initiated"
    assert high_timeline.events[1].keys["Device Instance ID"] == "SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
    assert high_timeline.events[1].keys["Status Value"] == "SUCCESS"
    assert high_timeline.events[1].files == r"NTFS:\Windows\INF\setupapi.dev.log"
    assert len(high_timeline.events[1].supporting['before']) == 1
    assert len(high_timeline.events[1].supporting['after']) == 0

    assert high_timeline.events[1].trigger == {
        'id': low_timeline.events[1].id,
        'description': "End of installation with device instance ID 'SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#0101192e17421d310eb90845e69173df47bc6b9ad0c88c0cb0cf7e8d8cc6a15#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'",
        'test_event': {
            'type': low_timeline.events[1].type,
            'evidence': r'Device Install \(.+\) - .+ -'
        },
        'provenance': low_timeline.events[1].provenance,
        'references': 'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/format-of-a-text-log-section',
        'keys': {},
    }
