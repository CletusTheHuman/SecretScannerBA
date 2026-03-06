SecretScannerBA

SecretScannerBA is a Python command-line tool that scans files or folders for hardcoded secrets such as API keys or tokens.

It uses regular expressions (regex) to detect common secret formats and reports where they appear in a file.

What It Detects

The scanner checks for patterns including:

Google API keys

GitHub personal access tokens

Slack bot tokens

AWS access key IDs

Mailgun API keys

These patterns were based on formats listed in the regextokens project.

How It Works

The user provides a file or folder path using the command line.

The program scans the file or every file in the folder.

Each line is checked against the regex patterns.

If a match is found, the program reports:

the file name

the line number

the detected key

How to Run

Scan a folder:

python secretscan.py test_files

Scan a single file:

python secretscan.py test_files/sample.txt

Optional logging example:

python secretscan.py test_files --log-level INFO
