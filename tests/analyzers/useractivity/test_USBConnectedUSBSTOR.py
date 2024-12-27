import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.USBConnectedRegUSBSTOR import FindUSBConnectedUSBSTOR

@pytest.fixture
def low_timeline():
    # Create 3 test event for windows registry modification artifacts

    # USBSTOR
    event = LowLevelEvent()
    event.id = 1
    event.date_time_min = "2024-08-29T07:54:10.113400+00:00"
    event.date_time_max = None
    event.type = "Content Modification Time-REG"
    event.path = r"NTFS:\Windows\System32\config\SYSTEM"
    event.evidence = r"[HKEY_LOCAL_MACHINE\System\ControlSet001\Enum\USBSTOR\Disk&Ven_Seagate&Prod_Expansion&Rev_0712\NAAXJ5NB&0] Address: [REG_DWORD_LE] 9 Capabilities: [REG_DWORD_LE] 16 ClassGUID: [REG_SZ] {4d36e967-e325-11ce-bfc1-08002be10318} CompatibleIDs: [REG_MULTI_SZ] [USBSTOR\Disk  USBSTOR\RAW  GenDisk] ConfigFlags: [REG_DWORD_LE] 0 ContainerID: [REG_SZ] {13b3a4df-ff65-5930-93d3-1ef7378756c2} DeviceDesc: [REG_SZ] @disk.inf %disk_devdesc%;Disk drive Driver: [REG_SZ] {4d36e967-e325-11ce-bfc1-08002be10318}\0001 FriendlyName: [REG_SZ] Seagate Expansion USB Device HardwareID: [REG_MULTI_SZ] [USBSTOR\DiskSeagate_Expansion_______0712  USBSTOR\DiskSeagate_Expansion_______  USBSTOR\DiskSeagate_  USBSTOR\Seagate_Expansion_______0  Seagate_Expansion_______0  USBSTOR\GenDisk  GenDisk] Mfg: [REG_SZ] @disk.inf %genmanufacturer%;(Standard disk drives) Service: [REG_SZ] disk"
    event.plugin = "REG-Registry Key-winreg/winreg_default"
    event.provenance = {
        'line_number': 1,
        'raw_entry': ["2024-08-29T07:54:10.113400+00:00",
                      "Content Modification Time",
                      "REG",
                      "Registry Key",
                      r"[HKEY_LOCAL_MACHINE\System\ControlSet001\Enum\USBSTOR\Disk&Ven_Seagate&Prod_Expansion&Rev_0712\NAAXJ5NB&0] Address: [REG_DWORD_LE] 9 Capabilities: [REG_DWORD_LE] 16 ClassGUID: [REG_SZ] {4d36e967-e325-11ce-bfc1-08002be10318} CompatibleIDs: [REG_MULTI_SZ] [USBSTOR\Disk  USBSTOR\RAW  GenDisk] ConfigFlags: [REG_DWORD_LE] 0 ContainerID: [REG_SZ] {13b3a4df-ff65-5930-93d3-1ef7378756c2} DeviceDesc: [REG_SZ] @disk.inf %disk_devdesc%;Disk drive Driver: [REG_SZ] {4d36e967-e325-11ce-bfc1-08002be10318}\0001 FriendlyName: [REG_SZ] Seagate Expansion USB Device HardwareID: [REG_MULTI_SZ] [USBSTOR\DiskSeagate_Expansion_______0712  USBSTOR\DiskSeagate_Expansion_______  USBSTOR\DiskSeagate_  USBSTOR\Seagate_Expansion_______0  Seagate_Expansion_______0  USBSTOR\GenDisk  GenDisk] Mfg: [REG_SZ] @disk.inf %genmanufacturer%;(Standard disk drives) Service: [REG_SZ] disk",
                      "winreg/winreg_default",
                      r"NTFS:\Windows\System32\config\SYSTEM",
                      "-"]
    }
    event.keys = None

    timeline = LowLevelTimeline()
    timeline.add_event(event)

    return timeline

def test_USBConnectedUSBSTOR(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindUSBConnectedUSBSTOR(low_timeline, start_id, end_id)

    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "USB Device Connected (Winreg USBSTOR)"
    assert high_timeline.events[0].description == "USB device connected with friendly name 'Seagate Expansion USB Device' (Winreg USBSTOR)."
    assert high_timeline.events[0].category == "User Activity"
    assert high_timeline.events[0].plugin == "REG-Registry Key-winreg/winreg_default"
    assert high_timeline.events[0].keys["ControlSet"] == "ControlSet001"
    assert high_timeline.events[0].keys["RegKeyName"] == "Disk&Ven_Seagate&Prod_Expansion&Rev_0712"
    assert high_timeline.events[0].keys["RegSubKeyName"] == "NAAXJ5NB&0"
    assert high_timeline.events[0].keys["ClassGUID"] == "4d36e967-e325-11ce-bfc1-08002be10318"
    assert high_timeline.events[0].keys["ContainerID"] == "13b3a4df-ff65-5930-93d3-1ef7378756c2"
    assert high_timeline.events[0].keys["DriverKey"] == "0001"
    assert high_timeline.events[0].keys["FriendlyName"] == "Seagate Expansion USB Device"
    assert high_timeline.events[0].files == r"NTFS:\Windows\System32\config\SYSTEM"

    assert high_timeline.events[0].trigger == {
        'id': low_timeline.events[0].id,
        'description': r"USB device connected with friendly name 'Seagate Expansion USB Device' in 'HKEY_LOCAL_MACHINE\System\ControlSet001\Enum\USBSTOR\'.",
        'test_event': {
            'type': low_timeline.events[0].type,
                'evidence': r"^\[HKEY_LOCAL_MACHINE\\System\\ControlSet00\d\\Enum\\USBSTOR\\[^\\]+\\[^\\]+\]"
        },
        'provenance': low_timeline.events[0].provenance,
        'references': 'https://doi.org/10.1016/j.diin.2019.02.004',
        'keys': {},
    }
