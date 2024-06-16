__author__ = 'Jony Patterson'

from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Bing Search"
analyser_category = "Web"

def Run(timeline, start_id=0, end_id=None):
    if end_id == None:
        end_id = len(timeline)

    return FindBingSearches(timeline, start_id, end_id)

def FindBingSearches(low_timeline, start_id, end_id):
    """Finds Bing searches based on URL structure"""

    test_event = LowLevelEvent()
    test_event.type = "URL Visit"
    test_event.path = "bing\.com/search"

    high_timeline = HighLevelTimeline()

    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event)

    for each_event in trigger_matches:
        if each_event.match(test_event):
            high_event = HighLevelEvent()
            high_event.add_time(each_event.date_time_min)
            high_event.evidence_source = each_event.evidence
            high_event.type = "Bing Search"
            url_components = ExtractDetailsFromBingSearchURL(each_event.path)
            search_term = CorrectlyFormattedSearchTerm(url_components)
            high_event.description = "Bing Search for '%s'" % search_term
            high_event.category = analyser_category
            high_event.device = each_event.evidence
            high_event.set_keys("Browser", GetBrowser(each_event.plugin))
            high_event.set_keys("URL", each_event.path)
            high_event.set_keys("Search_Term", search_term)

            reasoning = ReasoningArtefact()
            reasoning.id = each_event.id
            reasoning.description = "Bing search URL found in " + each_event.event_provenance.source
            reasoning.test_event = test_event

            high_event.trigger = reasoning

            high_timeline.add_event(high_event)


def ExtractDetailsFromBingSearchURL(url_string):
    """Splits up the URL on '&' """
    list_split_on_first_question_mark = url_string.split("?",1)
    if len(list_split_on_first_question_mark) > 1:
        list_split_on_ampersand = list_split_on_first_question_mark[1].split("&")
    else:
        list_split_on_ampersand = list_split_on_first_question_mark[0].split("&")
    return list_split_on_ampersand

def CorrectlyFormattedSearchTerm(url_list):
    """Finds search query and returns it as a string"""
    for each_entry in url_list:
        if each_entry.startswith('q='):
            search_text = each_entry.replace("q=", "")
            search_string = GetURLStringFromSearchText(search_text)
            return search_string

def GetURLStringFromSearchText(search_text):
    """Splits search query into a search string"""
    if '%20' in search_text:
        search_string = search_text.replace('%20', " ")
        return search_string
    elif '+' in search_text:
        search_string = search_text.replace('+', " ")
        return search_string
    else:
        return search_text

def GetBrowser(browser_string):
    """Extracts Browser from Plugin Name"""
    browser_data = browser_string.split(" ")[0]
    return browser_data