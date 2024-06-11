__author__ = ['Jony Patterson', 'Hudan Studiawan']

import re
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline


description = "Google Search"
analyser_category = "Web"

def Run(low_timeline, start_id=0, end_id=None):
    """Runs the Google Search analyser"""
    if end_id == None:
        end_id = len(low_timeline.events)
    
    return FindGoogleSearches(low_timeline, start_id, end_id)

def FindGoogleSearches(low_timeline, start_id, end_id):
    """Finds Google searches based on URL structure"""

    # Create a test event to match against
    test_event = LowLevelEvent()
    test_event.type = "Last Visited Time-WEBHIST"
    test_event.evidence = r'https?://(.+\.)(google)\.(?:com|co\.uk|fr)'

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id, end_id, test_event)

    # Extract details from matching events
    for each_low_event in trigger_matches:
        if each_low_event.match(test_event):
            if re.search("q=[^&]+?", each_low_event.evidence):
                url_components = ExtractDetailsFromGoogleSearchURL(each_low_event.evidence)
                if url_components != None:
                    # Create a high level event
                    high_event = HighLevelEvent()
                    high_event.add_time(each_low_event.date_time_min)
                    high_event.evidence_source = each_low_event.evidence
                    high_event.type = "Google Search"
                    search_term = CorrectlyFormatedSearchTerm(url_components)
                    high_event.description = "Google Search for '%s'" % search_term
                    high_event.category = analyser_category
                    high_event.device = each_low_event.plugin
                    high_event.files = each_low_event.path
                    high_event.set_keys("Browser", GetBrowser(each_low_event.plugin))
                    high_event.set_keys("Path", each_low_event.path)
                    high_event.set_keys("Search_Term", search_term)
                    high_event.supporting = low_timeline.get_surrounding_events(each_low_event.id, 5, 5)

                    # Create a reasoning artefact
                    reasoning = ReasoningArtefact()
                    reasoning.id = each_low_event.id
                    reasoning.description = f"Google search URL found in {','.join(each_low_event.provenance['raw_entry'])}"
                    reasoning.test_event = test_event

                    # Add the reasoning artefact to the high level event
                    high_event.trigger = reasoning

                    # Add the high level event to the high level timeline
                    high_timeline.add_event(high_event)
    
    return high_timeline


def ExtractDetailsFromGoogleSearchURL(url_string):
    """Splits up the URL first on '?' (if it is present) and then on '&' """
    result = re.search("q=", url_string)
    if result:
        list_split_on_first_question_mark = url_string.split("?",1)
        #print ("list:", list_split_on_first_question_mark)
        if len(list_split_on_first_question_mark) > 1:
            list_split_on_ampersand = list_split_on_first_question_mark[1].split("&")
        else:
            list_split_on_hashtag = list_split_on_first_question_mark[0].split("#")
            if len(list_split_on_hashtag) > 1:
                list_split_on_ampersand = list_split_on_hashtag[1].split("&")
            else:
                list_split_on_ampersand = list_split_on_hashtag[0].split("&")
        #print("split on ampersand if no no ?:", list_split_on_ampersand)
        return list_split_on_ampersand
    else:
        return None

def CorrectlyFormatedSearchTerm(url_list):
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


class GoogleSearchException(Exception):
    """Exception in Chrome Parser"""
    def __init__(self, value):
        """Constructor for ChromeParserException"""
        self.value = value
    def __str__(self):
        """Returns string representation of ChromeParserException"""
        return repr(self.value)