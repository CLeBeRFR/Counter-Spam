#!/usr/bin/env python3
import os
import re
import json
import smtplib
import webbrowser
import imaplib
import email.charset
import email
import ipaddress
import whois
import getpass
from datetime import datetime
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

JUNK_FOLDER_NAME = "Junk"

def save_imap_credentials(filename):
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
    # Filename to store the IMAP credentials
    credential_file = "imap_credentials.json"

    if os.path.exists(credential_file) and os.path.getsize(credential_file) > 0:
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



def generate_mail_to_send(spammer_domain, spammer_mail, spam_subject, spammer_smtp, spam_date, spam_filename):
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
    file_part.add_header('Content-Disposition', 'attachment', filename=attachment_path)
    email.attach(file_part)

    # Send the email
    try:
        smtp_server.send_message(email)
    except Exception as exception_content:
        print("impossible to send the mail: ", exception_content)

    # Disconnect from the server
    smtp_server.quit()
    
def listFolders(imap):
    status, folders = imap.list()

    if status == 'OK':
        for folder in folders:
            folder_name = folder.decode('utf-8').split()[-1]


def establishConnection():
    credentials = load_imap_credentials()
    imap_server = ""

    if credentials:
        imap_server = credentials.get("imap_server")
        username = credentials.get("username")
        password = credentials.get("password")

    # Connexion au serveur IMAP
    imap = imaplib.IMAP4_SSL(imap_server, 993)

    # Authentification
    try:
        imap.login(username, password)
        print("✅ The authentication process has been successfully completed.")
    except:
        print("❌ An issue occurred during the authentication process.")
        exit(0)
    return imap

def closeConnection(imap):
    # Fermeture de la connexion
    imap.logout()
    print("Connection closed...")

def getContentOfMessage(msg):
    # if the email message is multipart
    if msg.is_multipart():
        # iterate over email parts
        for part in msg.walk():
            # extract content type of email
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            try:
                # get the email body
                body = part.get_payload(decode=True).decode()
            except:
                pass
            if content_type == "text/plain" and "attachment" not in content_disposition:
                # print text/plain emails and skip attachments
                print(body)
            elif "attachment" in content_disposition:
                print("Attachment detected")
                """
                # download attachment
                filename = part.get_filename()
                if filename:
                    folder_name = clean(subject)
                    if not os.path.isdir(folder_name):
                        # make a folder for this email (named after the subject)
                        os.mkdir(folder_name)
                    filepath = os.path.join(folder_name, filename)
                    # download attachment and save it
                    open(filepath, "wb").write(part.get_payload(decode=True))
                """
    else:
        # extract content type of email
        content_type = msg.get_content_type()
        # get the email body
        body = msg.get_payload(decode=True).decode()
        if content_type == "text/plain":
            # print only text email parts
            print(body)
    if content_type == "text/html":
        # if it's HTML, create a new HTML file and open it in browser
        folder_name = clean(subject)
        if not os.path.isdir(folder_name):
            # make a folder for this email (named after the subject)
            os.mkdir(folder_name)
        filename = "index.html"
        filepath = os.path.join(folder_name, filename)
        # write the file
        open(filepath, "w").write(body)
        # open in the default browser
        webbrowser.open(filepath)
    print("="*100)

def get_mail_subject(msg, response):
    """
    Retrieves the email subject from the 'Subject' header in the message.
    :param msg: The message object.
    :param response: The response object.
    :return: The email subject.
    """
    # Decode the email subject
    subject, encoding = decode_header(msg["Subject"])[0]

    if isinstance(subject, bytes):
        # Decode bytes to string using the specified encoding
        if encoding is None:
            encoding = 'utf-8'
        try:
            subject = str(subject, encoding, errors='replace')
        except:
            print("Error in decoding subject")
            subject = "Error in decoding subject"
    else:
        subject = str(subject)

    return subject


def get_mail_date(msg, response):
    """
    Retrieves the mail sending date from the 'Date' header in the message.
    :param msg: The message object.
    :param response: The response object.
    :return: The mail sending date.
    """
    # Retrieve the mail sending date
    date_mail, encoding = decode_header(msg["Date"])[0]
    return date_mail

    
def get_abuse_mail_with_report_abuse_to_header(msg, response):
    """
    Extracts the abuse mail address from the 'X-REPORT-ABUSE-TO' header in the message.
    :param msg: The message object.
    :param response: The response object.
    :return: A list containing the extracted abuse mail address, or an empty list if not found.
    """
    try:
        decode_header, encoding(msg['X-REPORT-ABUSE-TO'])[0]
    except:
        print("No header X-REPORT-ABUSE-TO")
        return   # No 'X-REPORT-ABUSE-TO' header found

    content = decode_header(msg['X-REPORT-ABUSE-TO'])[0]
    email_pattern = r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?)\b'
    report_match = re.search(email_pattern, str(content))
    report_mail = []

    if report_match:
        report_mail.append(report_match.group(1))

    return report_mail

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
    search_content = get_value_from_regex(msg, "Received-SPF", r"helo=(.*?);")

    if search_content is None:
        search_content = get_value_from_regex(msg, "Authentication-Results", r"smtp.mailfrom=(.*?);")

    return search_content

def get_value_from_regex(msg, searched_header, searched_regex):
    try:
        content, encoding = decode_header(msg[searched_header])[0]
    except:
        return None
    if isinstance(content, bytes):
        try:
            content = content.decode(encoding)
        except LookupError:
            subject = subject.decode('utf-8', errors='replace')
    if searched_regex is None:
        return content
    
    # Search for the patterns in the content
    match = re.search(searched_regex, str(content))
    if match is not None and len(content) != 0:
        match_value = match.group(1)
        print("FOUND",match_value)
        return match_value
    return None


def get_spammer_server(msg, response):
    try:
        content = decode_header(msg['Authentication-Results'])[0]
    except:
        return None
    
    regex = r'(?<=sender IP is )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    match = re.search(regex, str(content))

    if match:
        ip_address = match.group(0)
        return ip_address
    else:
        print("No IP address found for the spammer server")
        return None
        

def write_mail_to_disk(msg, response):
    """
    Writes the email message to disk.
    :param msg: The message object.
    :param response: The response object.
    :return: The file path of the saved message.
    """
    msg = email.message_from_bytes(response[1])
    filename = get_mail_subject(msg, response)
    path = "/tmp/" + filename + ".eml"

    try:
        with open(path, 'wb') as f:
            f.write(response[1])
            print("🖊️  New message written to disk: " + filename)
    except OSError as exc:
        if exc.errno == 36:
            print("Name too long, renaming...")
            path = "renamed_message.eml"
            with open(path, 'wb') as f:
                f.write(response[1])
                print("🖊️  New message written to disk: " + filename)
    
    return path

def iterate_over_mails(imap):
    """
    Iterates over emails in the specified folder and performs actions on each email.
    :param imap: The IMAP object.
    """
    status, messages = imap.select(JUNK_FOLDER_NAME)
    # Total number of emails
    total_messages = int(messages[0])
    N = 999999  # This value must be the number of mails in the specified folder.

    for i in range(total_messages, total_messages - N, -1):
        # Fetch the email message by ID
        try:
            res, msg = imap.fetch(str(i), "(RFC822)")
        except Exception:
            print("🧹 Email processing completed.")
            exit(0)

        for response in msg:
            if isinstance(response, tuple):
                msg = email.message_from_bytes(response[1])
                path_attachment = write_mail_to_disk(msg, response)
                mail_author = get_value_from_regex(msg, "From", None)
                date_mail = get_mail_date(msg, response)

                abuse_emails_list = get_abuse_mail(mail_author)
                spammer_smtp = ""
                subject = 'Report: Unsolicited Email from Suspicious Domain'
                if len(abuse_emails_list) == 0:
                    print("No abuse report address was found for the sender. Trying to detect SMTP directly...")
                    spammer_smtp = get_spammer_smtp(msg, response)
                    spammer_server_ip = get_spammer_server(msg, response)
                    abuse_emails_list = []
                    if spammer_smtp is not None:
                        abuse_emails_list.extend(get_abuse_mail(spammer_smtp))

                    if spammer_server_ip is not None:
                        abuse_emails_list.extend(get_abuse_mail(spammer_server_ip))  # Merge the both lists.
                        
                    if spammer_server_ip is None and spammer_smtp is None:
                        abuse_mail_returned = get_abuse_mail_with_report_abuse_to_header(msg, response)
                        if abuse_mail_returned is not None:
                            abuse_emails_list.append(abuse_mail_returned)

                    if len(abuse_emails_list) == 0:
                        print("❌ It has not been possible to find email abuse for the spammer SMTP or spammer server.")
                        continue
                    # Note: No get_domain_from_mail(mail_author) for the first parameter because mail is usurpated.
                    message = generate_mail_to_send(spammer_smtp, mail_author, subject, spammer_smtp, date_mail, path_attachment)
                else:
                    message = generate_mail_to_send(spammer_smtp, mail_author, subject, spammer_smtp, date_mail, path_attachment)

                print("✉️  An abuse report will be sent to the following email:")
                for abuse_email in abuse_emails_list:
                    print(abuse_email)

                receivers = abuse_emails_list
                send_email(receivers, subject, message, path_attachment)

        print("=" * 100 + '\n')


def get_domain_from_mail(mail_address):
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
    :param spammer_mail_address_or_IP: The spammer mail address or IP.
    :return: A list of abuse mail addresses.
    """
    spammer_domain_whois = None
    if "@" in spammer_mail_address_or_IP:
        spammer_domain_whois = whois.query(get_domain_from_mail(spammer_mail_address_or_IP))
    else:
        try:
            spammer_domain_whois = whois.query(spammer_mail_address_or_IP)
        except Exception:
            print(f"❌ Impossible to make a WHOIS request for IP {spammer_mail_address_or_IP} because the TLD is not supported by the python module whois.")

    abuse_emails_list = []
    if spammer_domain_whois is not None:
        if "@" in spammer_domain_whois.emails[0]:
            for email in spammer_domain_whois.emails:
                abuse_emails_list.append(email)

    return abuse_emails_list


if __name__ == '__main__':
    imap = establishConnection()
    listFolders(imap)
    iterate_over_mails(imap)
    closeConnection(imap)
