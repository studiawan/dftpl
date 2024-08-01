import sys
from dftpl.reader.CSVReader import CSVReader
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.analyzers.web.GoogleSearch import FindGoogleSearches
from dftpl.output.JSONWriter import JSONWriter

# Main function
if __name__ == '__main__':
    # Parse command line arguments
    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # Read the CSV file
    print('Reading CSV file ...')
    reader = CSVReader(input_path)

    # Create a list of LowLevelEvent objects
    print('Creating low-level timeline ...')
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(reader)

    # Run the Google Search analyzer
    print('Running Google Search analyzer ...')
    high_timeline = FindGoogleSearches(low_timeline, start_id=0, end_id=len(low_timeline.events))

    # Write the results to a JSON file
    print(f'Writing results to JSON file: {output_path} ...')
    json_writer = JSONWriter(high_timeline, output_path)
    json_writer.write()