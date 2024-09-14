import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.useractivity.FileDownloads import FileDownloaded


# file download
# 2023-12-26 00:37:07.947361+00:00,Creation Time,FILE,File stat,NTFS:\Users\User\Downloads\Firefox Installer.exe Type: file,filestat,NTFS:\Users\User\Downloads\Firefox Installer.exe,-

# supporting 
# 2023-12-26 00:37:23.781311+00:00,End Time,WEBHIST,Chrome History,https://cdn.stubdownloader.services.mozilla.com/builds/firefox-stub/en-US/win/ef5a2910edab879b9d22df3dbd331af666fa69b040641e1e053b2ea6ca113d26/Firefox%20Installer.exe (C:\Users\User\Downloads\Firefox Installer.exe). State: Complete. Received 349976 of 349976 bytes. Interrupt Reason: No Interrupt - Success. Danger Type: Content May Be Malicious - (eg: extension is exe but Safe Browsing has not finished checking the content).,sqlite/chrome_27_history,NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\History,-

@pytest.fixture
def low_timeline():
    # Create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:37:07.947361+00:00"
    event1.date_time_max = None
    event1.type = "Creation Time-FILE"
    event1.path = r"NTFS:\Users\User\Downloads\Firefox Installer.exe"
    event1.evidence = r"NTFS:\Users\User\Downloads\Firefox Installer.exe Type: file"
    event1.plugin = "FILE-File stat-filestat"
    event1.provenance = {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:37:07.947361+00:00",
                      "Creation Time",
                      "FILE",
                      "File stat",
                      r"NTFS:\Users\User\Downloads\Firefox Installer.exe Type: file",
                      "filestat",
                      r"NTFS:\Users\User\Downloads\Firefox Installer.exe",
                      "-"]
    }
    event1.keys = None

    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26 00:37:23.781311+00:00"
    event2.date_time_max = None
    event2.type = "Start Time-WEBHIST"
    event2.path = r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\History"
    event2.evidence = r"https://cdn.stubdownloader.services.mozilla.com/builds/firefox-stub/en-US/win/ef5a2910edab879b9d22df3dbd331af666fa69b040641e1e053b2ea6ca113d26/Firefox%20Installer.exe (C:\Users\User\Downloads\Firefox Installer.exe). State: Complete. Received 349976 of 349976 bytes. Interrupt Reason: No Interrupt - Success. Danger Type: Content May Be Malicious - (eg: extension is exe but Safe Browsing has not finished checking the content)."
    event2.plugin = "WEBHIST-Chrome History-sqlite/chrome_27_history"
    event2.provenance = {
        'line_number': 2,
        'raw_entry': ["2023-12-26 00:37:23.781311+00:00",
                      "Start Time",
                      "WEBHIST",
                      "Chrome History",
                      r"https://cdn.stubdownloader.services.mozilla.com/builds/firefox-stub/en-US/win/ef5a2910edab879b9d22df3dbd331af666fa69b040641e1e053b2ea6ca113d26/Firefox%20Installer.exe (C:\Users\User\Downloads\Firefox Installer.exe). State: Complete. Received 349976 of 349976 bytes. Interrupt Reason: No Interrupt - Success. Danger Type: Content May Be Malicious - (eg: extension is exe but Safe Browsing has not finished checking the content).",
                      "sqlite/chrome_27_history",
                      r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\History",
                      "-"]
    }
    event2.keys = None

    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)
    timeline.add_event(event2)

    return timeline

def test_FileDownloads(low_timeline):
    # file download
    start_id = 0
    end_id = 2
    high_timeline = FileDownloaded(low_timeline, start_id, end_id)

    # high level event
    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].id == 1
    assert high_timeline.events[0].date_time_min == "2023-12-26 00:37:07.947361+00:00"
    assert high_timeline.events[0].date_time_max == "2023-12-26 00:37:07.947361+00:00"
    assert high_timeline.events[0].evidence_source == r"NTFS:\Users\User\Downloads\Firefox Installer.exe Type: file"
    assert high_timeline.events[0].type == "File Downloaded"
    assert high_timeline.events[0].description == "File Downloaded (Firefox Installer.exe)"
    assert high_timeline.events[0].category == "User Activity"
    assert high_timeline.events[0].device == "FILE-File stat-filestat"
    assert high_timeline.events[0].files == r"NTFS:\Users\User\Downloads\Firefox Installer.exe"
    assert high_timeline.events[0].keys['File Name'] == "Firefox Installer.exe"
    assert high_timeline.events[0].keys['User'] == "User"

    # supporting events
    assert len(high_timeline.events[0].supporting) == 2
    assert high_timeline.events[0].supporting['before'] == []
    assert high_timeline.events[0].supporting['after'][0]['id'] == 2
    assert high_timeline.events[0].supporting['after'][0]['date_time_min'] == "2023-12-26 00:37:23.781311+00:00"
    assert high_timeline.events[0].supporting['after'][0]['type'] == "Start Time-WEBHIST"
    assert high_timeline.events[0].supporting['after'][0]['evidence'] == r"https://cdn.stubdownloader.services.mozilla.com/builds/firefox-stub/en-US/win/ef5a2910edab879b9d22df3dbd331af666fa69b040641e1e053b2ea6ca113d26/Firefox%20Installer.exe (C:\Users\User\Downloads\Firefox Installer.exe). State: Complete. Received 349976 of 349976 bytes. Interrupt Reason: No Interrupt - Success. Danger Type: Content May Be Malicious - (eg: extension is exe but Safe Browsing has not finished checking the content)."
    assert high_timeline.events[0].supporting['after'][0]['path'] == r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\History"
    assert high_timeline.events[0].supporting['after'][0]['plugin'] == "WEBHIST-Chrome History-sqlite/chrome_27_history"
    assert high_timeline.events[0].supporting['after'][0]['provenance']['line_number'] == 2
    assert high_timeline.events[0].supporting['after'][0]['provenance']['raw_entry'] == [
        "2023-12-26 00:37:23.781311+00:00",
        "Start Time",
        "WEBHIST",
        "Chrome History",
        r"https://cdn.stubdownloader.services.mozilla.com/builds/firefox-stub/en-US/win/ef5a2910edab879b9d22df3dbd331af666fa69b040641e1e053b2ea6ca113d26/Firefox%20Installer.exe (C:\Users\User\Downloads\Firefox Installer.exe). State: Complete. Received 349976 of 349976 bytes. Interrupt Reason: No Interrupt - Success. Danger Type: Content May Be Malicious - (eg: extension is exe but Safe Browsing has not finished checking the content).",
        "sqlite/chrome_27_history",
        r"NTFS:\Users\User\AppData\Local\Microsoft\Edge\User Data\Default\History",
        "-"
    ]
    assert high_timeline.events[0].supporting['after'][0]['keys'] == None
    
    # reasoning artefact
    assert len(high_timeline.events[0].trigger) == 7
    assert high_timeline.events[0].trigger['id'] == 1
    assert high_timeline.events[0].trigger['description'] == "Created file in downloads folder: Firefox Installer.exe"
    assert high_timeline.events[0].trigger['test_event']['type'] == "Creation Time-FILE"
    assert high_timeline.events[0].trigger['test_event']['evidence'] == r"\\Users\\[^\\]+\\Downloads"
    assert high_timeline.events[0].trigger['provenance'] == {
        'line_number': 1,
        'raw_entry': ["2023-12-26 00:37:07.947361+00:00",
                      "Creation Time",
                      "FILE",
                      "File stat",
                      r"NTFS:\Users\User\Downloads\Firefox Installer.exe Type: file",
                      "filestat",
                      r"NTFS:\Users\User\Downloads\Firefox Installer.exe",
                      "-"]
    }
    assert high_timeline.events[0].trigger['source-0']['description_source'] == "File Downloaded (Firefox Installer.exe) from https://cdn.stubdownloader.services.mozilla.com/builds/firefox-stub/en-US/win/ef5a2910edab879b9d22df3dbd331af666fa69b040641e1e053b2ea6ca113d26/"
    assert high_timeline.events[0].trigger['source-0']['test_event_source']['type'] == "Start Time-WEBHIST"
    assert high_timeline.events[0].trigger['source-0']['test_event_source']['evidence'] == r"https?:\/\/[^\s]+\/Firefox%20Installer\.exe"

