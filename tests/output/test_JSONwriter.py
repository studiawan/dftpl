import pytest
from dftpl.output.JSONWriter import JSONWriter
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact

import json
import os


@pytest.fixture
def json_writer(tmpdir):
    timeline = LowLevelTimeline()
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:43:28.536120+00:00"
    event1.date_time_max = None
    event1.evidence_source = "install.tmp File reference: 134110-12 Parent file reference: 244418-2 Update source:  Update reason: USN_REASON_FILE_DELETE  USN_REASON_CLOSE"
    event1.type = "Metadata Modification Time-FILE"
    event1.description = "Metadata Modification Time"
    event1.category = "FILE"
    event1.device = "NTFS USN change"
    event1.files = r"NTFS:\$Extend\$UsnJrnl:$J"
    event1.keys = None
    event1.supporting = "-"
    timeline.add_event(event1)

    event2 = LowLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26 00:45:45.817000+00:00"
    event2.date_time_max = None
    event2.evidence_source = "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK"
    event2.type = "Last Visited Time-WEBHIST"
    event2.description = "Last Visited Time"
    event2.category = "WEBHIST"
    event2.device = "Firefox History"
    event2.files = r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite"
    event2.keys = None
    event2.supporting = "sqlite/firefox_history"
    timeline.add_event(event2)

    json_path = os.path.join(tmpdir, 'test.json')
    return JSONWriter(timeline, json_path)


def test_to_dict(json_writer):
    expected_dict = {
        0: {
            'id': 1,
            'date_time_min': "2023-12-26 00:43:28.536120+00:00",
            'date_time_max': None,
            'evidence_source': "install.tmp File reference: 134110-12 Parent file reference: 244418-2 Update source:  Update reason: USN_REASON_FILE_DELETE  USN_REASON_CLOSE",
            'type': "Metadata Modification Time-FILE",
            'description': "Metadata Modification Time",
            'category': "FILE",
            'device': "NTFS USN change",
            'files': r"NTFS:\$Extend\$UsnJrnl:$J",
            'keys': None,
            'supporting': "-"
        },
        1: {
            'id': 2,
            'date_time_min': "2023-12-26 00:45:45.817000+00:00",
            'date_time_max': None,
            'evidence_source': "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK",
            'type': "Last Visited Time-WEBHIST",
            'description': "Last Visited Time",
            'category': "WEBHIST",
            'device': "Firefox History",
            'files': r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite",
            'keys': None,
            'supporting': "sqlite/firefox_history"
        }
    }

    assert json_writer.to_dict() == expected_dict


def test_write(json_writer):
    expected_dict = {
        '0': {
            'id': 1,
            'date_time_min': "2023-12-26 00:43:28.536120+00:00",
            'date_time_max': None,
            'evidence_source': "install.tmp File reference: 134110-12 Parent file reference: 244418-2 Update source:  Update reason: USN_REASON_FILE_DELETE  USN_REASON_CLOSE",
            'type': "Metadata Modification Time-FILE",
            'description': "Metadata Modification Time",
            'category': "FILE",
            'device': "NTFS USN change",
            'files': r"NTFS:\$Extend\$UsnJrnl:$J",
            'keys': None,
            'supporting': "-"
        },
        '1': {
            'id': 2,
            'date_time_min': "2023-12-26 00:45:45.817000+00:00",
            'date_time_max': None,
            'evidence_source': "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK",
            'type': "Last Visited Time-WEBHIST",
            'description': "Last Visited Time",
            'category': "WEBHIST",
            'device': "Firefox History",
            'files': r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite",
            'keys': None,
            'supporting': "sqlite/firefox_history"
        }
    }

    json_writer.write()

    with open(json_writer.json_path, 'r') as file:
        written_dict = json.load(file)

    print(written_dict)
    print(expected_dict)
    assert written_dict == expected_dict


# START : UNIT TEST USING HIGHLEVELTIMELINE
@pytest.fixture
def high_level_timeline_writer(tmpdir):
    timeline = HighLevelTimeline()
    event1 = HighLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 23:30:24.568036+00:00"
    event1.date_time_max = None
    event1.evidence_source = "[HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty)"
    event1.type = "User created"
    event1.description = "User 'root' created"
    event1.category = "Windows"
    event1.device = "REG-Registry Key-winreg/winreg_default"
    event1.files = "NTFS:\Windows\System32\config\SAM"
    event1.keys = {
        "Username": "root"
    }
    reasoning = ReasoningArtefact()
    # Test event for entry in SAM for a user
    test_event = LowLevelEvent()
    test_event.plugin = "REG-Registry Key-winreg/winreg_default"
    test_event.type = "Content Modification Time-REG"
    # SAM path is in the "evidence" variable"
    test_event.evidence = r"\\SAM\\Domains\\Account\\Users\\Names\\.+$"
    reasoning.id = 1
    # Long string wrapped in [] because otherwise, long string will be broken up into multiline string and wrapped in () while the test expects multiline string without ()
    reasoning.description = [
        "Last Write for SAM Registry entry NTFS:\Windows\System32\config\SAM in 2023-12-26T23:30:24.568036+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty),winreg/winreg_default,NTFS:\\Windows\\System32\\config\\SAM,-"]
    reasoning.test_event = test_event
    event1.trigger = reasoning
    event1.supporting = "-"

    event2 = HighLevelEvent()
    event2.id = 2
    event2.date_time_min = "2023-12-26 00:45:45.817000+00:00"
    event2.date_time_max = None
    event2.evidence_source = "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK"
    event2.type = "Google Search"
    event2.description = "Google Search for 'how to perform sql injection attack'"
    event2.category = "Web"
    event2.device = "WEBHIST-Firefox History-sqlite/firefox_history"
    event2.files = r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite"
    event2.keys = {
        "Browser": "WEBHIST-Firefox",
        "Path": "NTFS:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\my7atezl.default-release\\places.sqlite",
        "Search_Term": "how to perform sql injection attack"
    }
    reasoning = ReasoningArtefact()
    # Test event
    test_event = LowLevelEvent()
    test_event.type = "Last Visited Time-WEBHIST"
    test_event.evidence = r'https?://(.+\.)(google)\.(?:com|co\.uk|fr)'
    reasoning.id = 2
    reasoning.description = [
        "Google search URL found in 2023-12-26 00:45:45.817000+00:00,Last Visited Time,WEBHIST,Firefox History,https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK,sqlite/firefox_history,NTFS:\\Users\\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite,-"]
    reasoning.test_event = test_event
    event2.trigger = reasoning
    event2.supporting = "-"

    timeline.add_event(event1)
    timeline.add_event(event2)

    json_path = os.path.join(tmpdir, 'test.json')
    return JSONWriter(timeline, json_path)


def test_to_dict_high(high_level_timeline_writer):
    expected_dict = {
        0: {
            "id": 1,
            "date_time_min": "2023-12-26 23:30:24.568036+00:00",
            "date_time_max": None,
            "evidence_source": "[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty)",
            "type": "User created",
            "description": "User 'root' created",
            "category": "Windows",
            "device": "REG-Registry Key-winreg/winreg_default",
            "files": "NTFS:\\Windows\\System32\\config\\SAM",
            "keys": {
                "Username": "root"
            },
            "trigger": {
                "id": 1,
                "test event": {
                    "id": None,
                    "date_time_min": None,
                    "date_time_max": None,
                    "type": "Content Modification Time-REG",
                    "path": None,
                    "evidence": "\\\\SAM\\\\Domains\\\\Account\\\\Users\\\\Names\\\\.+$",
                    "provenance": None,
                    "plugin": "REG-Registry Key-winreg/winreg_default",
                    "keys": {}
                },
                # Long string wrapped in [] because otherwise, long string will be broken up into multiline string and wrapped in () while the test expects multiline string without ()
                "description": [
        "Last Write for SAM Registry entry NTFS:\Windows\System32\config\SAM in 2023-12-26T23:30:24.568036+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty),winreg/winreg_default,NTFS:\\Windows\\System32\\config\\SAM,-"]

            },
            'supporting': "-"
        },
        1: {
            "id": 2,
            "date_time_min": "2023-12-26 00:45:45.817000+00:00",
            "date_time_max": None,
            "evidence_source": "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK",
            "type": "Google Search",
            "description": "Google Search for 'how to perform sql injection attack'",
            "category": "Web",
            "device": "WEBHIST-Firefox History-sqlite/firefox_history",
            "files": "NTFS:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\my7atezl.default-release\\places.sqlite",
            "keys": {
                "Browser": "WEBHIST-Firefox",
                "Path": "NTFS:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\my7atezl.default-release\\places.sqlite",
                "Search_Term": "how to perform sql injection attack"
            },
            "trigger": {
                "id": 2,
                "description": [
                    "Google search URL found in 2023-12-26 00:45:45.817000+00:00,Last Visited Time,WEBHIST,Firefox History,https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK,sqlite/firefox_history,NTFS:\\Users\\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite,-"],
                "test event": {
                    "id": None,
                    "date_time_min": None,
                    "date_time_max": None,
                    "type": "Last Visited Time-WEBHIST",
                    "path": None,
                    "evidence": "https?://(.+\\.)(google)\\.(?:com|co\\.uk|fr)",
                    "provenance": None,
                    "plugin": None,
                    "keys": {}
                }
            },
            'supporting': "-"
        }
    }
    assert high_level_timeline_writer.to_dict() == expected_dict


def test_write_high_timeline(high_level_timeline_writer):
    expected_dict = {
        '0': {
            "id": 1,
            "date_time_min": "2023-12-26 23:30:24.568036+00:00",
            "date_time_max": None,
            "evidence_source": "[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty)",
            "type": "User created",
            "description": "User 'root' created",
            "category": "Windows",
            "device": "REG-Registry Key-winreg/winreg_default",
            "files": "NTFS:\\Windows\\System32\\config\\SAM",
            "keys": {
                "Username": "root"
            },
            "trigger": {
                "id": 1,
                #Long string is broken up into multiline string and wrapped in angle brackets '[]' during unit test
                "description": [
                    "Last Write for SAM Registry entry NTFS:\\Windows\\System32\\config\\SAM in 2023-12-26T23:30:24.568036+00:00,Content Modification Time,REG,Registry Key,[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\root] (default): [UNKNOWN] (empty),winreg/winreg_default,NTFS:\\Windows\\System32\\config\\SAM,-"],
                "test event": {
                    "id": None,
                    "date_time_min": None,
                    "date_time_max": None,
                    "type": "Content Modification Time-REG",
                    "path": None,
                    "evidence": "\\\\SAM\\\\Domains\\\\Account\\\\Users\\\\Names\\\\.+$",
                    "provenance": None,
                    "plugin": "REG-Registry Key-winreg/winreg_default",
                    "keys": {}
                }
            },
            'supporting': "-"
        },
        '1': {
            "id": 2,
            "date_time_min": "2023-12-26 00:45:45.817000+00:00",
            "date_time_max": None,
            "evidence_source": "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK",
            "type": "Google Search",
            "description": "Google Search for 'how to perform sql injection attack'",
            "category": "Web",
            "device": "WEBHIST-Firefox History-sqlite/firefox_history",
            "files": "NTFS:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\my7atezl.default-release\\places.sqlite",
            "keys": {
                "Browser": "WEBHIST-Firefox",
                "Path": "NTFS:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\my7atezl.default-release\\places.sqlite",
                "Search_Term": "how to perform sql injection attack"
            },
            "trigger": {
                "id": 2,
                "description": [
                    "Google search URL found in 2023-12-26 00:45:45.817000+00:00,Last Visited Time,WEBHIST,Firefox History,https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK,sqlite/firefox_history,NTFS:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\my7atezl.default-release\\places.sqlite,-"],
                "test event": {
                    "id": None,
                    "date_time_min": None,
                    "date_time_max": None,
                    "type": "Last Visited Time-WEBHIST",
                    "path": None,
                    "evidence": "https?://(.+\\.)(google)\\.(?:com|co\\.uk|fr)",
                    "provenance": None,
                    "plugin": None,
                    "keys": {}
                }
            },
            'supporting': "-"
        }
    }
    high_level_timeline_writer.write()

    with open(high_level_timeline_writer.json_path, 'r') as file:
        written_dict = json.load(file)

    print(written_dict)
    print(expected_dict)
    assert written_dict == expected_dict
