import re


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