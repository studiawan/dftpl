# /reader/YAMLReader.py

import yaml
from dftpl.rules.Rule import Rule


class YAMLReader:
    def __init__(self, file_path):
        self.file_path = file_path

    def read(self) -> Rule:
        with open(self.file_path, "r") as file:
            rule_data = yaml.safe_load(file)

        return Rule.from_yaml(rule_data)
