# Emojifi Deobfuscator

**Emojifi Deobfuscator** is a Python tool designed to deobfuscate Python code that has been obfuscated using emoticons and symbols. This tool is useful for those who want to decode code that has been intentionally made harder to read using emoji-based obfuscation techniques.

## Features

- **Automatic extraction of mapping and encoded data**: Automatically detects and extracts the emoji mapping and obfuscated data from the Python code.
- **Decoding based on the mapping**: Uses an emoji mapping to decode the obfuscated code and recover the original Python code.
- **Support for various obfuscation modes**: Works with different types of obfuscation that use various emoji and symbol patterns.
- **Python script compatibility**: Can be used to deobfuscate Python scripts that have been modified to obscure the source code.
- **Command-line interface**: The tool can be run directly from the command line to quickly and easily deobfuscate Python scripts.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/Emojifi-Deobfuscator.git
    cd Emojifi-Deobfuscator
    ```

2. Install the dependencies:

    ```bash
    Dipendences are arleady installed by default on python
    ```

## Usage

### Deobfuscating a Python file

Once you have downloaded and set up the project, you can deobfuscate a Python file using the following command:

```bash
python emojifi_deobfuscator.py -i input_file.py -o output_file.py
