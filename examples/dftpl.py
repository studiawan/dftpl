import dftpl.analyzers.web.GoogleSearch as GoogleSearch
import dftpl.analyzers.web.BingSearch as BingSearch
import dftpl.analyzers.web.WebVisits as WebVisits
import dftpl.analyzers.web.AllImagesFromCache as AllImagesFromCache
import dftpl.analyzers.windows.LastShutdown as LastShutdown
import dftpl.analyzers.windows.ProcessCreation as ProcessCreation
import dftpl.analyzers.windows.ProgramOpened as ProgramOpened
import dftpl.analyzers.useractivity.FileDownloads as FileDownloads
import dftpl.analyzers.useractivity.RecentFileAccess as RecentFileAccess
from dftpl.reader.CSVReader import CSVReader
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.timelines.HighLevelTimeline import MergeHighLevelTimeline
from dftpl.output.JSONWriter import JSONWriter


# Main function
def main():
    # Read the arguments from the command line
    input_path = 'input_csv_file_here'
    output_path = 'output_json_file_here'
    event_type = 'type_of_event_here'

    # Read the CSV file
    print('Reading CSV file ...')
    reader = CSVReader(input_path)

    # Create a list of LowLevelEvent objects
    print('Creating low-level timeline ...')
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(reader)

    # Create a list of high-level timeline
    high_timelines = []

    # List of search analyzers
    # Dictionary mapping event types to analyzers
    event_analyzers = {
        'google-search': [GoogleSearch],
        'bing-search': [BingSearch],
        'web-visits': [WebVisits],
        'images-from-cache': [AllImagesFromCache],
        'last-shutdown': [LastShutdown],
        'process-creation': [ProcessCreation],
        'program-opened': [ProgramOpened],
        'file-downloads': [FileDownloads],
        'recent-file-access': [RecentFileAccess]
    }

    # Default analyzers
    default_analyzers = [
        GoogleSearch, BingSearch, WebVisits, AllImagesFromCache,
        LastShutdown, ProcessCreation, ProgramOpened,
        FileDownloads, RecentFileAccess
    ]

    # Get analyzers based on event_type, or use default analyzers
    analyzers = event_analyzers.get(event_type, default_analyzers)

    # Run each search analyzer
    for analyzer in analyzers:
        print(f'Running {analyzer.description} analyzer ...')
        high_timeline = analyzer.Run(low_timeline)
        if high_timeline:
            high_timelines.append(high_timeline)

    # Merge the high-level timelines
    print('Merging high-level timelines ...')
    merge_timelines = MergeHighLevelTimeline(high_timelines)
    merged_high_timelines = merge_timelines.merge()

    # Write the results to a JSON file
    print(f'Writing results to JSON file: {output_path} ...')
    json_writer = JSONWriter(merged_high_timelines, output_path)
    json_writer.write()
