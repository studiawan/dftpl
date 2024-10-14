import argparse
import os
import dftpl.analyzers.yaml.ReadFromYamlAnalyzer as ReadFromYamlAnalyzer
import  dftpl.analyzers.web.GoogleSearch as GoogleSearch
from dftpl.reader.CSVReader import CSVReader
from dftpl.reader.YAMLReader import YAMLReader
from dftpl.timelines.LowLevelTimeline import LowLevelTimeline
from dftpl.timelines.HighLevelTimeline import MergeHighLevelTimeline
from dftpl.output.JSONWriter import JSONWriter


# Main function
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Forensic event reconstruction tool.')
    parser.add_argument('-i', '--input_path', action='store', required=True, type=str, help='Path to a CSV file from plaso.')
    parser.add_argument('-o', '--output_path', action='store', required=True, type=str, help='Output file path.')
    parser.add_argument('-t', '--type', action='store', required=False, type=str, help='Type of the timeline to create.')

    # Read the arguments from the command line
    args = parser.parse_args()
    input_path = args.input_path
    output_path = args.output_path
    event_type = args.type

    # Read the CSV file
    print('Reading CSV file ...')
    reader = CSVReader(input_path)

    # Create a list of LowLevelEvent objects
    print('Creating low-level timeline ...')
    low_timeline = LowLevelTimeline()
    low_timeline.create_timeline(reader)

    # Create a list of high-level timeline
    high_timelines = []

    # List of search rules
    # Dictionary mapping event types to rules
    event_analyzers = {
        'google-search': ["/web/GoogleSearch.yaml"],
        'bing-search': ["/web/BingSearch.yaml"],
    }

    # Default rules
    default_rules = [
        "/web/GoogleSearch.yaml"
    ]

    # Get rules based on event_type, or use default rules
    rules = event_analyzers.get(event_type, default_rules)

    # Read the YAML rules
    yaml_contents = []
    for rule in rules:
        yaml_file_path = os.path.join(os.path.dirname(__file__), 'rules' + rule) 
        reader = YAMLReader(yaml_file_path)
        yaml_content = reader.read()
        yaml_contents.append(yaml_content)

    
    # Run each rules with the analyzer
    for yaml_content in yaml_contents:
        high_timeline = ReadFromYamlAnalyzer.Run(low_timeline, yaml_content)
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
