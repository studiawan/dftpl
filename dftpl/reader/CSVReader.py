import csv

class CSVReader:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def read_csv(self):
        with open(self.file_path, 'r') as file:
            csv_reader = csv.reader(file)
            for index, row in enumerate(csv_reader):
                yield index, row
        