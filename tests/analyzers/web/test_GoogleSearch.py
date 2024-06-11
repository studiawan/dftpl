import pytest
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.analyzers.web.GoogleSearch import FindGoogleSearches


@pytest.fixture
def low_timeline():
    # Create a test event to match against
    event1 = LowLevelEvent()
    event1.id = 1
    event1.date_time_min = "2023-12-26 00:45:45.817000+00:00" 
    event1.date_time_max = None
    event1.type = "Last Visited Time-WEBHIST"
    event1.path =   r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite"
    event1.evidence = "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK"
    event1.plugin = "WEBHIST-Firefox History-sqlite/firefox_history"
    event1.provenance = {
        'line_number': 3,
        'raw_entry': ["2023-12-26 00:45:45.817000+00:00",
                      "Last Visited Time",
                      "WEBHIST",
                      "Firefox History",
                      "https://www.google.com/search?q=how+to+perform+sql+injection+attack&sca_esv=593660335&source=hp&ei=JCKKZa2nJpyQ4-EPxMC0gAc&iflsig=AO6bgOgAAAAAZYowNLiilF7qtRZRa87l8OG8Glw10jwB&ved=0ahUKEwitye3776uDAxUcyDgGHUQgDXAQ4dUDCAk&uact=5&oq=how+to+perform+sql+injection+attack&gs_lp=Egdnd3Mtd2l6IiNob3cgdG8gcGVyZm9ybSBzcWwgaW5qZWN0aW9uIGF0dGFjazIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIHEAAYgAQYEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YEzIIEAAYFhgeGBMyCBAAGBYYHhgTMggQABgWGB4YE0i1ZVDZFVjRWHABeACQAQCYAewHoAH2Y6oBDzAuMS40LjQuMy4yLjguMbgBA8gBAPgBAagCCsICEBAAGAMYjwEY5QIY6gIYjAPCAhAQLhgDGI8BGOUCGOoCGIwDwgIFEAAYgATCAggQLhiABBjUAsICCBAAGIAEGLEDwgILEAAYgAQYsQMYgwHCAgUQLhiABMICBBAAGAPCAggQLhiABBixA8ICBhAAGBYYHsICCRAAGIAEGA0YEw&sclient=gws-wiz (how to perform sql injection attack - Penelusuran Google) [count: 1] Host: www.google.com visited from: https://www.google.com/?gws_rd=ssl (www.google.com) (URL not typed directly) Transition: LINK",
                      "sqlite/firefox_history",
                      r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite",
                      "-"]
    }
    event1.keys = None

    # Add events to timeline
    timeline = LowLevelTimeline()
    timeline.add_event(event1)

    return timeline

def test_FindGoogleSearches(low_timeline):
    start_id = 0
    end_id = 1
    high_timeline = FindGoogleSearches(low_timeline, start_id, end_id)
    
    assert len(high_timeline.events) == 1
    assert high_timeline.events[0].type == "Google Search"
    assert high_timeline.events[0].description == "Google Search for 'how to perform sql injection attack'"
    assert high_timeline.events[0].category == "Web"
    assert high_timeline.events[0].device == "WEBHIST-Firefox History-sqlite/firefox_history"
    assert high_timeline.events[0].keys["Browser"] == "WEBHIST-Firefox"
    assert high_timeline.events[0].keys["Path"] == r"NTFS:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\my7atezl.default-release\places.sqlite"
    assert high_timeline.events[0].keys["Search_Term"] == "how to perform sql injection attack"
