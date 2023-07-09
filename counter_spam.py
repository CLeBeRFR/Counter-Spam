#!/usr/bin/env python3
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import os
import json
import imaplib
import email
import re
import whois
from email.header import decode_header

JUNK_FOLDER_NAME = "Junk"
REMOVE_JUNK_AFTER_PROCESSING = True
DEBUG_MODE = False
EML_OUTPUT_PATH = "/tmp/"


def save_imap_credentials(filename):
    """
    Prompts the user for IMAP and SMTP server details, as well as IMAP username and password,
    and saves them to a file in JSON format.

    Args:
        filename (str): The name of the file to save the credentials to.
    """
    imap_server = input("IMAP Server: ")
    smtp_server = input("SMTP Server: ")
    imap_username = input("IMAP Username: ")
    imap_password = getpass.getpass("IMAP Password: ")

    credentials = {
        "imap_server": imap_server,
        "smtp_server": smtp_server,
        "username": imap_username,
        "password": imap_password
    }

    with open(filename, "w") as file:
        json.dump(credentials, file)

    print(f"Credentials saved to {filename}.")


def load_imap_credentials():
    """
    Loads IMAP credentials from a JSON file if it exists and is not empty,
    otherwise prompts the user to save the credentials to the file.

    Returns:
        dict or None: The loaded credentials as a dictionary, or None if the file doesn't exist or is empty.
    """
    # Filename to store the IMAP credentials
    credential_file = "imap_credentials.json"

    if os.path.exists(credential_file) and os.path.getsize(
            credential_file) > 0:
        try:
            with open(credential_file, "r") as file:
                credentials = json.load(file)
                return credentials
        except FileNotFoundError:
            print(f"File '{credential_file}' not found.")
        except json.JSONDecodeError:
            print(f"Invalid JSON format in '{credential_file}'.")
        return None
    else:
        # Save IMAP credentials to a file
        save_imap_credentials(credential_file)
        # Load IMAP credentials from the file
        credentials = load_imap_credentials()
        return credentials


def generate_mail_to_send(
        spammer_domain,
        spammer_mail,
        spam_subject,
        spammer_smtp,
        spam_date,
        spam_filename):
    """
    Generates a report email to be sent regarding a suspicious email believed to be spam.

    Args:
        spammer_domain (str): The domain from which the suspicious email originated.
        spammer_mail (str): The sender of the suspicious email.
        spam_subject (str): The subject of the suspicious email.
        spammer_smtp (str): The SMTP server associated with the suspicious email.
        spam_date (str): The date and time the suspicious email was received.
        spam_filename (str): The name of the file containing the suspicious email.

    Returns:
        str: The generated report email as a string.
    """

    REPORT_TEXT = f"""
Dear Madam, Dear Sir,
I am writing to report an unsolicited email that I received, which I believe to be spam.
The email originated from the domain {spammer_domain} and contained content that raised concerns about its legitimacy.

Below are the details of the suspicious email:
    Sender: {spammer_mail}
    Subject: {spam_subject}
    SMTP: {spammer_smtp}
    Date/Time Received: {spam_date}

Upon reviewing the email, I noticed several indicators that suggest it may be spam or potentially malicious.
I urge you to investigate this matter further to ensure the security and integrity of your email services.
Please find attached a copy of the email for your reference. The file is named "{spam_filename}".
Should you require any additional information or assistance, please do not hesitate to reach out to me.

Thank you for your attention to this matter. Your prompt action in addressing and mitigating potential spam issues is greatly appreciated.
Best regards.
"""
    return REPORT_TEXT


def send_email(receivers, subject, message, attachment_path):
    """
    Sends an email with optional attachment to the specified receivers.

    Args:
        receivers (str or list): The email addresses of the receivers.
        subject (str): The subject of the email.
        message (str): The body of the email.
        attachment_path (str): The file path of the attachment, if any.
    """
    # Connect to the SMTP server
    credentials = load_imap_credentials()
    if credentials:
        smtp_server = credentials.get("smtp_server")
        username = credentials.get("username")
        password = credentials.get("password")

    smtp_server = smtplib.SMTP(smtp_server, 587)
    smtp_server.starttls()  # Enable TLS encryption
    smtp_server.login(username, password)

    # Create a multipart message
    email = MIMEMultipart()
    email['Subject'] = subject
    email['From'] = username
    if isinstance(receivers, list):
        email['To'] = ', '.join(receivers)
    else:
        email['To'] = receivers

    # Add the message body
    body = MIMEText(message)
    email.attach(body)

    # Attach the file
    with open(attachment_path, 'rb') as attachment:
        file_part = MIMEApplication(attachment.read())

    # Set the filename in the attachment
    file_part.add_header(
        'Content-Disposition',
        'attachment',
        filename=attachment_path)
    email.attach(file_part)

    is_sent = False
    # Send the email
    try:
        if DEBUG_MODE:
            raise RuntimeError("Debug mode enabled")
        smtp_server.send_message(email)
        is_sent = True
    except Exception as exception_content:
        print("⚠️ Unable to send the email:", exception_content)
    # Disconnect from the server
    smtp_server.quit()
    return is_sent


def remove_junk_emails(imap):
    """
    Remove all emails from the Junk folder.

    Args:
        imap (IMAP4): An instance of the IMAP4 class representing the IMAP connection.

    Returns:
        None
    """

    if not REMOVE_JUNK_AFTER_PROCESSING:
        print("🗑️  Junk are not deleted because functionnality not enabled.")
        return 0

    # Search for all emails in the Junk folder
    _, data = imap.search(None, 'ALL')
    email_ids = data[0].split()

    # Delete each email in the Junk folder
    for email_id in email_ids:
        imap.store(email_id, '+FLAGS', '\\Deleted')

    # Permanently remove the deleted emails
    imap.expunge()


def list_folders(imap):
    """
    Lists the folders in the IMAP mailbox.

    Args:
        imap: The IMAP client instance.

    Returns:
        list: A list of folder names.
    """
    status, folders = imap.list()

    if status == 'OK':
        for folder in folders:
            folder_name = folder.decode('utf-8').split()[-1]
            # Process each folder name as needed


def establish_connection():
    """
    Establishes a connection to the IMAP server and performs authentication.

    Returns:
        imaplib.IMAP4_SSL: The IMAP client instance.
    """
    credentials = load_imap_credentials()
    imap_server = ""

    if credentials:
        imap_server = credentials.get("imap_server")
        username = credentials.get("username")
        password = credentials.get("password")

    # Connection to the IMAP server
    imap = imaplib.IMAP4_SSL(imap_server, 993)

    # Authentication
    try:
        imap.login(username, password)
        print("✅ The authentication process has been successfully completed.")
    except BaseException:
        print("❌ An issue occurred during the authentication process.")
        exit(0)
    return imap


def close_connection(imap):
    """
    Closes the connection to the IMAP server.

    Args:
        imap: The IMAP client instance.
    """
    # Closing the connection
    imap.logout()
    print("Connection closed...")


def get_content_of_message(msg):
    """
    Retrieves and processes the content of an email message.

    Args:
        msg: The email message.

    """
    content_type = ""
    # If the email message is multipart
    if msg.is_multipart():
        # Iterate over email parts
        for part in msg.walk():
            # Extract content type of email
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            try:
                # Get the email body
                body = part.get_payload(decode=True).decode()
            except BaseException:
                pass
            if content_type == "text/plain" and "attachment" not in content_disposition:
                # Print text/plain emails and skip attachments
                print(body)
            elif "attachment" in content_disposition:
                print("Attachment detected")
                """
                # Download attachment
                filename = part.get_filename()
                if filename:
                    folder_name = clean(subject)
                    if not os.path.isdir(folder_name):
                        # Make a folder for this email (named after the subject)
                        os.mkdir(folder_name)
                    filepath = os.path.join(folder_name, filename)
                    # Download attachment and save it
                    open(filepath, "wb").write(part.get_payload(decode=True))
                """
    else:
        # Extract content type of email
        content_type = msg.get_content_type()
        # Get the email body
        body = msg.get_payload(decode=True).decode()
        if content_type == "text/plain":
            # Print only text email parts
            print(body)
    if content_type == "text/html":
        # If it's HTML, create a new HTML file and open it in a browser
        folder_name = clean(subject)
        if not os.path.isdir(folder_name):
            # Make a folder for this email (named after the subject)
            os.mkdir(folder_name)
        filename = "index.html"
        filepath = os.path.join(folder_name, filename)
        # Write the file
        open(filepath, "w").write(body)
        # Open in the default browser
        webbrowser.open(filepath)
    print("=" * 100)


def get_mail_subject(msg, response):
    """
    Retrieves the email subject from the 'Subject' header in the message.

    Args:
        msg: The message object.
        response: The response object.

    Returns:
        The email subject.
    """
    # Decode the email subject
    subject, encoding = decode_header(msg["Subject"])[0]

    if isinstance(subject, bytes):
        # Decode bytes to string using the specified encoding
        if encoding is None:
            encoding = 'utf-8'
        try:
            subject = str(subject, encoding, errors='replace')
        except BaseException:
            print("Error in decoding subject")
            subject = "Error in decoding subject"
    else:
        subject = str(subject)

    return subject


def get_mail_date(msg, response):
    """
    Retrieves the mail sending date from the 'Date' header in the message.

    Args:
        msg: The message object.
        response: The response object.

    Returns:
        The mail sending date.
    """
    # Retrieve the mail sending date
    date_mail, encoding = decode_header(msg["Date"])[0]
    return date_mail


def get_spammer_smtp(msg, response):
    """
    Extracts the SMTP information related to a spammer from the email message headers.

    Args:
        msg (email.message.Message): The email message object.
        response: Unused argument.

    Returns:
        str: The value of the SMTP information (helo value or smtp.mailfrom value)
             associated with the spammer, or None if not found.
    """
    # Search for the helo value in the 'Received-SPF' header
    search_content = get_value_from_regex(msg, "Received-SPF", r"helo=(.*?);")
    if search_content is None:
        # If helo value is not found, search for smtp.mailfrom value in
        # 'Authentication-Results' header
        search_content = get_value_from_regex(
            msg, "Authentication-Results", r"smtp.mailfrom=(.*?);")

    return search_content


def get_value_from_regex(msg, searched_header, searched_regex):
    """
    Extracts a value from the message header using a regular expression pattern.

    Args:
        msg (email.message.Message): The email message object.
        searched_header (str): The header to search for.
        searched_regex (str): The regular expression pattern to search for.

    Returns:
        str or None: The extracted value if found, or None if not found.
    """
    content = None
    try:
        content, encoding = decode_header(msg[searched_header])[0]
    except KeyError:
        return None
    except TypeError as e:
        pass

    if isinstance(content, bytes):
        try:
            content = content.decode(encoding)
        except BaseException:
            # If encoding lookup fails, replace the decoding errors with
            # Unicode replacement characters
            content = content.decode('utf-8', errors='replace')

    if searched_regex is None:
        return content

    # Search for the patterns in the content
    try:
        match = re.search(searched_regex, str(content))
        if match is not None and len(content) != 0:
            match_value = match.group(1)
            return match_value
    except Exception:
        pass

    return None


def write_mail_to_disk(msg, response):
    """
    Writes the email message to disk.

    Args:
        msg (email.message.Message): The message object.
        response: The response object.

    Returns:
        str: The file path of the saved message.
    """
    msg = email.message_from_bytes(response[1])
    filename = get_mail_subject(msg, response)
    path = EML_OUTPUT_PATH + filename + ".eml"

    try:
        with open(path, 'wb') as f:
            f.write(response[1])
            print("🖊️  New message written to disk: " + filename)
    except OSError as exc:
        path = EML_OUTPUT_PATH + "renamed_message.eml"
        with open(path, 'wb') as f:
            f.write(response[1])
            print("🖊️  New message written to disk: " + filename)
    return path


def iterate_over_mails(imap):
    """
    Iterates over emails in the specified folder and performs actions on each email.

    Args:
        imap: The IMAP object.
    """
    status, messages = imap.select(JUNK_FOLDER_NAME)

    total_messages = 0
    try:
        # Total number of emails
        total_messages = int(messages[0])
    except BaseException:
        print("❌ Impossible to get number of messages. Maybe",
              JUNK_FOLDER_NAME, "folder does not exists?")
        exit(0)

    # This value must be the number of mails in the specified folder.
    N = 999999

    for i in range(total_messages, total_messages - N, -1):
        # Fetch the email message by ID
        try:
            res, msg = imap.fetch(str(i), "(RFC822)")
        except Exception:
            print("🧹 Email processing completed.")
            return 0
        for response in msg:
            if isinstance(response, tuple):
                msg = email.message_from_bytes(response[1])
                path_attachment = write_mail_to_disk(msg, response)
                mail_author = get_value_from_regex(msg, "From", None)
                date_mail = get_mail_date(msg, response)
                abuse_emails_list = get_abuse_mail(mail_author)
                spammer_smtp = ""
                subject = 'Report: Unsolicited Email from Suspicious Domain'

                try:
                    mail_smtp = get_value_from_regex(
                        msg,
                        "Authentication-Results",
                        r'header\.i=([^;\s]+)')
                    abuse_mail = get_abuse_mail(mail_smtp)
                    abuse_emails_list.extend(abuse_mail)
                except:
                    pass
                    
                if len(abuse_emails_list) == 0:
                    print(
                        "No abuse report address was found for the sender. Trying to detect SMTP directly...")
                    spammer_smtp = get_spammer_smtp(msg, response)
                    spammer_server_ip = get_value_from_regex(
                        msg,
                        "Authentication-Results",
                        r'(?<=sender IP is )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                    abuse_emails_list = []

                    if spammer_smtp is not None:
                        abuse_emails_list.extend(get_abuse_mail(spammer_smtp))

                    if spammer_server_ip is not None:
                        # Merge the both lists.
                        abuse_emails_list.extend(
                            get_abuse_mail(spammer_server_ip))

                    if spammer_server_ip is None and spammer_smtp is None:
                        abuse_mail_returned = get_value_from_regex(
                            msg,
                            "X-REPORT-ABUSE-TO",
                            r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?)\b')
                        if abuse_mail_returned is not None:
                            abuse_emails_list.append(abuse_mail_returned)

                    if len(abuse_emails_list) == 0:
                        print(
                            "❌ It has not been possible to find email abuse for the spammer SMTP or spammer server.")
                        continue

                    # Note: No get_domain_from_mail(mail_author) for the first
                    # parameter because mail is usurpated.
                    message = generate_mail_to_send(
                        spammer_smtp, mail_author, subject, spammer_smtp, date_mail, path_attachment)
                else:
                    message = generate_mail_to_send(
                        spammer_smtp, mail_author, subject, spammer_smtp, date_mail, path_attachment)

                print("✉️  An abuse report will be sent to the following email:")
                for abuse_email in abuse_emails_list:
                    print(abuse_email)
                receivers = abuse_emails_list
                is_sent = send_email(
                    receivers, subject, message, path_attachment)

        print("=" * 100 + '\n')


def get_domain_from_mail(mail_address):
    """
    Extracts the domain from an email address.

    Args:
        mail_address (str): The email address.

    Returns:
        str: The domain extracted from the email address.
    """
    # Regular expression pattern to match email-like patterns
    pattern = r'[\w\.-]+@([\w\.-]+)'
    # Find all matches of the pattern in the string
    match = re.search(pattern, mail_address)
    # Extract unique domain from the matches
    spammer_domain = match.group(1)
    return spammer_domain


def get_abuse_mail(spammer_mail_address_or_IP):
    """
    Retrieves abuse mail addresses associated with the provided spammer mail address or IP.

    Args:
        spammer_mail_address_or_IP (str): The spammer mail address or IP.

    Returns:
        list: A list of abuse mail addresses.
    """
    spammer_domain_whois = None
    if "@" in spammer_mail_address_or_IP:
        spammer_domain_whois = whois.query(
            get_domain_from_mail(spammer_mail_address_or_IP))
    else:
        try:
            spammer_domain_whois = whois.query(spammer_mail_address_or_IP)
        except Exception:
            print(
                f"❌ Impossible to make a WHOIS request for IP {spammer_mail_address_or_IP} because the TLD is not supported by the python module whois.")

    abuse_emails_list = []

    if spammer_domain_whois is not None:
        try:
            if "@" in spammer_domain_whois.emails[0]:
                for email in spammer_domain_whois.emails:
                    abuse_emails_list.append(email)
        except Exception:
            pass
    return abuse_emails_list


if __name__ == '__main__':
    # Establish IMAP connection
    imap = establish_connection()

    # List folders
    list_folders(imap)

    # Iterate over emails
    iterate_over_mails(imap)

    # Remove all junk mails after processing
    remove_junk_emails(imap)

    # Close IMAP connection
    close_connection(imap)
