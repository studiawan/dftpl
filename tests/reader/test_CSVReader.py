import pytest
import csv
from dftpl.reader.CSVReader import CSVReader

@pytest.fixture
def csv_reader():
    csv.field_size_limit(10000000) 
    file_path = 'test_data/13-sample.csv'
    
    return CSVReader(file_path)

def test_read_csv(csv_reader):
    expected_data = [
        (0, 
         ["datetime", 
          "timestamp_desc", 
          "source",
          "source_long", 
          "message", 
          "parser",
          "display_name",
          "tag"]),
        (1, 
         ["2023-12-26 00:43:28.536120+00:00",
          "Metadata Modification Time",
          "FILE",
          "NTFS USN change",
          "install.tmp File reference: 134110-12 Parent file reference: 244418-2 Update source:  Update reason: USN_REASON_FILE_DELETE  USN_REASON_CLOSE",
          "usnjrnl",
          "NTFS:\$Extend\$UsnJrnl:$J",
          "-"]),
        (2, 
         ["2023-12-26 00:43:28.211450+00:00",
          "Metadata Modification Time",
          "FILE",
          "NTFS USN change",
          "install.tmp File reference: 134110-13 Parent file reference: 244418-2 Update source:  Update reason: USN_REASON_DATA_EXTEND  USN_REASON_FILE_CREATE",
          "usnjrnl",
          "NTFS:\$Extend\$UsnJrnl:$J",
          "-"])
    ]
    actual_data = list(csv_reader.read_csv())
    assert actual_data[0:3] == expected_data