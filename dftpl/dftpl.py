import argparse
from dftpl.reader.CSVReader import CSVReader
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
import dftpl.analyzers.web.GoogleSearch as GoogleSearch
from dftpl.output.JSONWriter import JSONWriter


# Main function
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Forensic event reconstruction tool.')
    parser.add_argument('-i', '--input_path', action='store', required=True, type=str, help='Path to a CSV file from plaso.')
    parser.add_argument('-o', '--output_path', action='store', required=True, type=str, help='Output file path.')

    # Read the arguments from the command line
    args = parser.parse_args()
    input_path = args.input_path
    output_path = args.output_path

    # Read the CSV file
    print('Reading CSV file ...')
    reader = CSVReader(input_path)

    # Create a list of LowLevelEvent objects
    print('Creating low-level timeline ...')
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(reader)

    # Run the Google Search analyzer
    print('Running Google Search analyzer ...')
    high_timeline = GoogleSearch.Run(low_timeline)

    # Write the results to a JSON file
    print(f'Writing results to JSON file: {output_path} ...')
    json_writer = JSONWriter(high_timeline, output_path)
    json_writer.write()
