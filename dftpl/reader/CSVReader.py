import csv

class CSVReader:
    def __init__(self, file_path: str):
        self.file_path = file_path
        csv.field_size_limit(1000000)

    def read_csv(self):
        # encoding utf-8 to avoid UnicodeDecodeError: 'charmap' codec can't decode byte xxxx in position xxxx
        with open(self.file_path, 'r', encoding="utf-8") as file:
            csv_reader = csv.reader(file)
            for index, row in enumerate(csv_reader):
                yield index, row
        