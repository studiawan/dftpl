__author__ = 'Jony Patterson'


import logging
import re
from dftpl.timelines.HighLevelTimeline import HighLevelTimeline
from dftpl.events.LowLevelEvent import LowLevelEvent
from dftpl.events.HighLevelEvent import HighLevelEvent, ReasoningArtefact


description = "Recent File Access"
analyser_category = "User Activity"

def Run(timeline, start_id=0, end_id=None):
    """Runs the Recent File Access analyser"""
    if end_id == None:
        end_id = len(timeline)

    return RecentFileAccess(timeline, start_id, end_id)

def RecentFileAccess(low_timeline, start_id, end_id):
    """Finds recent file accesses"""
    
    # Create a test event to match against
    test_event_dict = GetTestEventDictionary()

    # Create a high level timeline to store the results
    high_timeline = HighLevelTimeline()

    # Find matching events
    trigger_matches = low_timeline.find_matching_events_in_id_range(start_id,end_id, test_event_dict)

    for each_event in trigger_matches:
        matched_trigger = each_event.match_any_test_event(test_event_dict)
        if matched_trigger:
            #create high-level event
            high_level_event = HighLevelEvent()
            high_level_event.add_time(each_event.date_time_min)
            high_level_event.add_time(each_event.date_time_max)

            #get specific file path from matched event
            matched_file_details = GetMatchedFileDetailsFromTrigger(each_event, test_event_dict[matched_trigger], matched_trigger)
            edited_test_dict = GetSpecificTestEventDict(matched_file_details["Link File Path"], matched_file_details["Registry Path"], matched_file_details["Index Path"])

            results = low_timeline.get_list_of_matches_in_sub_timeline(edited_test_dict,start=each_event.date_time_min-30*1, end=each_event.date_time_min+60*1)

            if results:
                for each_match in results:
                    each_match_event = each_match[0]
                    each_match_type = each_match[1]

                    #update times for additional matched event
                    high_level_event.add_time(each_match_event.date_time_min)
                    high_level_event.add_time(each_match_event.date_time_max)

                    #add as supporting artefacts
                    supporting = ReasoningArtefact()
                    supporting.description = "%s (%s)" % (each_match_type, each_match_event.path)
                    supporting.id = each_match_event.id
                    supporting.test_event = edited_test_dict[each_match_type]
                    high_level_event.AddSupportingEvidenceArtefact(supporting)

            # If the matched event was a link file, the time the event is actually the creation time of the .lnk file
            # Need to go and find it
            if each_event.plugin == "LinkFile Parser":
                events_for_link_file_in_file_system = low_timeline.get_events_related_to_a_path(each_event.event_provenance.source)
                for each_file_system_event in events_for_link_file_in_file_system:
                    if each_file_system_event.type == "Created" and each_file_system_event.plugin == "MFT":
                        high_level_event.add_time(each_file_system_event.date_time_min)
                    else:
                        # there is a problem as you can't get a time for this event
                        # Going to have to ignore this event as the time is incorrect
                        logging.error("Found a link file for potential file access (%s) but could not locate MFT entry for .lnk. Skipped." % each_event.event_provenance.source)
                        continue
            else:
                high_level_event.add_time(each_event.date_time_min)


            # if the matched event was an index.dat we need to make modifications to the path
            # i.e. change %20 to a space and trim the file:/// from the start
            # also separate out the drive letter
            the_updated_path = "SHOULD NOT SEE THIS - CHECK FILE ACCESS ANALYSER"
            if each_event.plugin == "IExplorer Parser":
                #print("IE path before:%s" % each_event.path )
                the_updated_path = re.sub("file:///", "", each_event.path)
                the_updated_path = re.sub("%20", " ", the_updated_path)

                if re.match("[A-Z]:/",the_updated_path):
                    # path starts with drive letter, remove and put in keys
                    high_level_event.set_keys("Drive Letter", the_updated_path[0:2])
                    the_updated_path = the_updated_path[2:]

                #print("IE path after:%s" % high_level_event.path)


            #Add trigger artefact
            trigger = ReasoningArtefact()

            if matched_trigger == "Recent from Office MRU":
                trigger.description = "%s (%s)" % (matched_trigger, StripDriveLetter(each_event.keys["Item 1"]))
                high_level_event.description = "File Accessed (%s)" % (StripDriveLetter(each_event.keys["Item 1"]))
            elif matched_trigger == "Recent from Applet":
                trigger.description = "%s (%s)" % (matched_trigger, StripDriveLetter(each_event.keys["File1"]))
                high_level_event.description = "File Accessed (%s)" % (StripDriveLetter(each_event.keys["File1"]))
            elif matched_trigger == "Recent from Index.dat":
                trigger.description = "%s (%s)" % (matched_trigger, each_event.path)
                high_level_event.description = "File Accessed (%s)" % the_updated_path
            else:
                trigger.description = "%s (%s)" % (matched_trigger, each_event.path)
                high_level_event.description = "File Accessed (%s)" % each_event.path

            trigger.id = each_event.id
            trigger.test_event = test_event_dict[matched_trigger]
            high_level_event.trigger = trigger
            high_level_event.category = analyser_category
            high_level_event.type = "File Access"
            high_level_event.device = each_event.evidence
            high_level_event.evidence_source = each_event.evidence

            if "Link File Path" in matched_file_details:
                high_level_event.AddFile(matched_file_details["Link File Path"])
            if "Filename" in matched_file_details:
                high_level_event.set_keys("Filename", matched_file_details["Filename"])
            if "Drive Letter" in matched_file_details:
                high_level_event.set_keys("Drive Letter", matched_file_details["Drive Letter"])
            if "Extension" in matched_file_details:
                high_level_event.set_keys("Extension", matched_file_details["Extension"])

            high_timeline.add_event(high_level_event)


def StripDriveLetter(path):
    """Strips any drive letter from the path"""
    if re.match("[A-Z]:/",path):
        # path starts with drive letter, remove and put in keys
        the_updated_path = path[2:]
        return the_updated_path
    else:
        return path


def GetTestEventDictionary():
    """Returns list of test events"""

    #link files
    recent_from_documents_and_settings_link_file_created = LowLevelEvent()
    recent_from_documents_and_settings_link_file_created.plugin = "LinkFile Parser"
    recent_from_documents_and_settings_link_file_created.type = "Created"
    recent_from_documents_and_settings_link_file_created.event_provenance.source = "/Documents and Settings/(.*?)/Recent/((.*?)\.lnk)"
    recent_from_documents_and_settings_link_file_created.path = "/(.+/(.+(\.[A-z]{3,4})))$"

    recent_from_link_file_created = LowLevelEvent()
    recent_from_link_file_created.plugin = "LinkFile Parser"
    recent_from_link_file_created.type = "Created"
    recent_from_link_file_created.event_provenance.source = "/Users/(.*?)/AppData/Roaming/Microsoft/Windows/Recent/((.*?)\.lnk)"
    recent_from_link_file_created.path = "/(.+/(.+(\.[A-z]{3,4})))$"

    #mru
    recent_from_office_mru = LowLevelEvent()
    recent_from_office_mru.plugin = "Registry Parser"
    recent_from_office_mru.type = "Last Updated"
    recent_from_office_mru.path = ".+/Software/Microsoft/Office/.+/(.+)/File MRU"
    recent_from_office_mru.keys["Item 1"] = r".+\*((.{3})(.+\\(.+(\.[A-z]{3,4}))))$"

    #index.dat
    recent_from_index_dot_dat = LowLevelEvent()
    recent_from_index_dot_dat.plugin = "IExplorer Parser"
    recent_from_index_dot_dat.type = "URL Visit"
    recent_from_index_dot_dat.path = "file:///([A-z]{1}:/)(.+/(.+(\.[A-z]{3,4})))$"

    #Applet entries in Registry
    recent_from_applet = LowLevelEvent()
    recent_from_applet.plugin = "Registry Parser"
    recent_from_applet.type = "Last Updated"
    recent_from_applet.path = "Software/Microsoft/Windows/CurrentVersion/Applets/.*?/Recent File List"
    recent_from_applet.keys["File1"] = r"(.{1}:\\)(.*\\(.+(\.[A-z]{3,4})))$"

    test_event_dict = {"Link file created in Documents & Settings": recent_from_documents_and_settings_link_file_created,
                       "Link file created in Recent Folder": recent_from_link_file_created,
                       "Recent from Office MRU": recent_from_office_mru,
                       "Recent from Index.dat": recent_from_index_dot_dat,
                       "Recent from Applet": recent_from_applet}

    return test_event_dict

def GetMatchedFileDetailsFromTrigger(matched_event, test_event, matched_trigger):
    """Extracts file details from matched event"""
    file_details_dict = {}
    if matched_trigger == "Link file created in Documents & Settings" or matched_trigger == "Link file last written in Documents & Settings" or matched_trigger == "Link file created in Recent Folder" \
    or matched_trigger == "Link File last written in Recent folder":
        matched_file_path = re.search(test_event.path, matched_event.path)
        file_details_dict["Link File Path"] = matched_file_path.group(1)
        file_details_dict["Filename"] = matched_file_path.group(2)
        file_details_dict["Extension"] = matched_file_path.group(3)
        file_details_dict["Index Path"] = re.sub(" ", "%20", file_details_dict["Link File Path"])
        file_details_dict["Registry Path"] = re.sub("/", "\\\\", file_details_dict["Link File Path"])
        if "allocated_drive_letter" in matched_event.keys:
            file_details_dict["Drive Letter"] = matched_event.keys["allocated_drive_letter"]
        return file_details_dict

    elif matched_trigger == "Recent from Office MRU":
        matched_file_path = re.search(test_event.keys["Item 1"], matched_event.keys["Item 1"])
        file_details_dict["Drive Letter"] = matched_file_path.group(2)
        file_details_dict["Registry Path"] = matched_file_path.group(3)
        file_details_dict["Filename"] = matched_file_path.group(4)
        file_details_dict["Extension"] = matched_file_path.group(5)
        file_details_dict["Link File Path"] = re.sub("\\\\", "/", file_details_dict["Registry Path"])
        file_details_dict["Index Path"] = re.sub(" ", "%20",file_details_dict["Link File Path"])

        return file_details_dict

    elif matched_trigger == "Recent from Index.dat":
        #TODO:  This is a dirty hack - Needs a better way of implementing
        matched_file_details = re.search(test_event.path, matched_event.path)
        file_details_dict["Drive Letter"] = matched_file_details.group(1)
        file_details_dict["Index Path"] = matched_file_details.group(2)
        file_details_dict["Filename"] = matched_file_details.group(3)
        file_details_dict["Extension"] = matched_file_details.group(4)
        file_details_dict["Link File Path"] = re.sub("%20", " ", file_details_dict["Index Path"])
        file_details_dict["Registry Path"] = re.sub("/", "\\\\", file_details_dict["Link File Path"])

        return file_details_dict

    elif matched_trigger == "Recent from Applet":
        matched_file_path = re.search(test_event.keys["File1"], matched_event.keys["File1"])
        file_details_dict["Drive Letter"] = matched_file_path.group(1)
        file_details_dict["Registry Path"] = matched_file_path.group(2)
        file_details_dict["Filename"] = matched_file_path.group(3)
        file_details_dict["Extension"] = matched_file_path.group(4)
        file_details_dict["Link File Path"] = re.sub("\\\\", "/", file_details_dict["Registry Path"])
        file_details_dict["Index Path"] = re.sub(" ", "%20",file_details_dict["Link File Path"])

        return file_details_dict

def GetSpecificTestEventDict(link_path, registry_path, index_path):
    """Edits each test event to incorporate the matched file path"""
    edited_test_dict = {}

    #link files
    recent_from_documents_and_settings_link_file_created = LowLevelEvent()
    recent_from_documents_and_settings_link_file_created.plugin = "Mounted File System|MFT"
    recent_from_documents_and_settings_link_file_created.type = "Created"
    recent_from_documents_and_settings_link_file_created.path = "/Documents and Settings/(.*?)/Recent/((.*?)\.lnk)"
    #recent_from_documents_and_settings_link_file_created.path = "/%s$" % link_path

    recent_from_link_file_created = LowLevelEvent()
    recent_from_link_file_created.plugin = "Mounted File System|MFT"
    recent_from_link_file_created.type = "Created"
    recent_from_link_file_created.path = "/Users/(.*?)/AppData/Roaming/Microsoft/Windows/Recent/((.*?)\.lnk)"
    #recent_from_link_file_created.path = "/%s$" % link_path
    #recent_from_link_file_created.path = "/%s$" % link_path

    #mru
    recent_from_office_mru = LowLevelEvent()
    recent_from_office_mru.plugin = "Registry Parser"
    recent_from_office_mru.type = "Last Updated"
    recent_from_office_mru.path = ".+/Software/Microsoft/Office/.+/(.+)/File MRU"
    registry_regex = re.sub('\\\\', '\\\\\\\\' ,registry_path)
    recent_from_office_mru.keys["Item 1"] = "%s$" % registry_regex

    #index.dat
    recent_from_index_dot_dat = LowLevelEvent()
    recent_from_index_dot_dat.plugin = "IExplorer Parser"
    recent_from_index_dot_dat.type = "URL Visit"
    recent_from_index_dot_dat.path = "%s$" % index_path

    #Applet entries in Registry
    recent_from_applet = LowLevelEvent()
    recent_from_applet.plugin = "Registry Parser"
    recent_from_applet.type = "Last Updated"
    recent_from_applet.path = "Software/Microsoft/Windows/CurrentVersion/Applets/.*?/Recent File List"
    applet_regex = re.sub('\\\\', '\\\\\\\\' ,registry_path)
    recent_from_applet.keys["File1"] = "%s$" % applet_regex

    edited_test_dict = {"Link file created in Documents & Settings": recent_from_documents_and_settings_link_file_created,
                       "Link file created in Recent Folder": recent_from_link_file_created,
                       "Recent from Office MRU": recent_from_office_mru,
                       "Recent from Index.dat": recent_from_index_dot_dat,
                       "Recent from Applet": recent_from_applet}

    return edited_test_dict

def GetCorrectLinkFileCreationTimeTestEvent(event_provenance_source):
    """Gets test event to extract link file creation time"""

    link_file_creation_time_test = LowLevelEvent()
    link_file_creation_time_test.path = event_provenance_source
    link_file_creation_time_test.type = "Created"
    link_file_creation_time_test.plugin = "MFT"

    link_file_test_event_dictionary = {}
    link_file_test_event_dictionary["Link File Created"] = link_file_creation_time_test
    return link_file_test_event_dictionary


    