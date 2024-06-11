# dftpl
dftpl (PyDFT plaso) is a forensic event reconstruction tool. It uses the PyDFT (dft) analyzer for high-level event extraction [[1]](#1) from log2timeline plaso (pl) CSV files [[2]](#2), using them as the source of low-level events.

## Installation

1. Create a virtual environment using Anaconda or other tools. Open your terminal and run the command: 
   
   `conda create --name dftpl python=3.12`

2. Once the virtual environment is created successfully, activate it with:

    `conda activate dftpl`

3. Clone the `dftpl` repository:

    `git clone https://github.com/studiawan/dftpl.git`

4. Navigate to the root project directory:

    `cd dftpl`

5. Install the package:

    `pip install .`

   or:

    `pip install -e .`

   If you want to develop or edit the package.

6. You can check if the package is successfully installed in your virtual environment using:
      
    `pip list`
      
   Look for `dftpl` in the list to confirm. In addition, run `dftpl -h` command on your terminal. It should print:

    ```
    usage: dftpl [-h] -i INPUT_PATH -o OUTPUT_PATH

    Forensic event reconstruction tool.

    options:
    -h, --help          show this help message and exit
    -i INPUT_PATH, --input_path INPUT_PATH
                        Path to a CSV file from plaso.
    -o OUTPUT_PATH, --output_path OUTPUT_PATH
                        Output file path.
    ```
7. Remember, every time you need to use this package, ensure that you activate the virtual environment using `conda activate dftpl`.

## Quick start

1. Activate the virtual environment:

    `conda activate dftpl`

2. Reconstruct a high-level timeline:

    `dftpl -i test_data/13.csv -o test_data/13.json`

## References

<a id="1">[1]</a>  Hargreaves, C., & Patterson, J. (2012). An automated timeline reconstruction approach for digital forensic investigations. Digital Investigation, 9, S69-S79.

<a id="2">[2]</a> https://github.com/log2timeline/plaso