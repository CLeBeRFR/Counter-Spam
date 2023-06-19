![Counter-Spam](./logo.png){: width="256px" }
# Email Spam Detection and Reporting
This Python project provides functionality to detect and report suspicious emails believed to be spam. It allows users to connect to an IMAP server, analyze email messages, and generate reports to be sent to the appropriate authorities.

## Prerequisites
- Python 3
- `email` module
- `imaplib` module
- `smtplib` module
- `whois` module

## Usage
1. Clone the repository:

```bash
git clone https://github.com/CLeBeRFR/Counter-Spam.git
```

2. Install the required dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Run the script:
```bash
python spam_detection.py
```

Follow the prompts to enter the IMAP and SMTP server details, as well as the IMAP username and password.
The script will connect to the IMAP server, analyze the emails in the Junk folder, and send abuse reports for emails.

## Features
- Connect to an IMAP server and authenticate using provided credentials.
- Analyze email messages for spam indicators.
- Send abuse report email to the designated authorities.
- Remove junk emails from the Junk folder.

## Configuration
The IMAP and SMTP server details, as well as the IMAP username and password, can be saved to a JSON file for convenience. The script will prompt the user to save the credentials when they are entered for the first time.

To change the default configurations, modify the following variables in the script:

- `JUNK_FOLDER_NAME`: Name of the Junk folder.
- `DEBUG_MODE`: Enable/disable debug mode.
- `EML_OUTPUT_PATH`: Path to save the suspicious email in EML format.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request to improve this project.

## Acknowledgements
This project makes use of the following libraries:
`email` - Python library for parsing, handling, and generating email messages.
`imaplib` - Python library for accessing and manipulating IMAP mailboxes.
`smtplib` - Python library for sending email using the Simple Mail Transfer Protocol (SMTP).
`whois` - Python library for retrieving WHOIS information of domains.

## Disclaimer
This project is intended for educational purposes only. Use it responsibly and at your own risk.