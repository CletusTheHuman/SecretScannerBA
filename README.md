Secret ScannerBA is a python command line tool that scans files or folders for hardcoded secrets such as api keys or tokens.

It scans for patterns including
- Google api keys
- Github personal access tokens
- Slack bot tokens
- AWS access key IDs
- Mailgun API keys


HOW IT WORKS
1. The user provides a file or folder path using the command line
2. The program scans the file or every file in the folder
3. Each line is checked against the regex patterns
4. If a match is found the program reports:
   - The file name
   - The line number
   - The detected key
