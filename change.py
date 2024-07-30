import streamlit as st
from groq import Groq
import os
import base64
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from datetime import datetime, timedelta
from email.mime.text import MIMEText

# Set up the necessary scopes and credentials file
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send','https://www.googleapis.com/auth/gmail.modify']


# Function to get authenticated Gmail API service
def get_gmail_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            credentials_json = st.secrets['GOOGLE_CREDENTIALS_JSON']
            if not credentials_json:
                raise ValueError("No credentials.json found in environment variables.")
            credentials_info = json.loads(credentials_json)
            flow = InstalledAppFlow.from_client_config(credentials_info, SCOPES)
            auth_url, _ = flow.authorization_url(prompt='consent')

            st.write("Please go to this URL and authorize the application:")
            st.write(auth_url)

            code = st.text_input("Enter the authorization code here:")
            if code:
                flow.fetch_token(code=code)
                creds = flow.credentials
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_message_details(message):
    """Extracts the subject and content of an email message."""
    headers = message['payload']['headers']
    subject = next(header['value'] for header in headers if header['name'] == 'Subject')
    
    if 'data' in message['payload']['body']:
        body_data = message['payload']['body']['data']
        body_decoded = base64.urlsafe_b64decode(body_data).decode('utf-8')
        return subject, body_decoded
    else:
        parts = message['payload'].get('parts', [])
        for part in parts:
            if part['mimeType'] == 'text/plain':
                body_data = part['body'].get('data', '')
                body_decoded = base64.urlsafe_b64decode(body_data).decode('utf-8')
                return subject, body_decoded
            elif part['mimeType'] == 'text/html':
                body_data = part['body'].get('data', '')
                body_decoded = base64.urlsafe_b64decode(body_data).decode('utf-8')
                return subject, body_decoded
    return subject, "No content available"

def fetch_gmail(sender_email):

    date = st.date_input('Date', key='date')
    message_content = ''
    subject = ''

    if st.button('Fetch Gmail Messages', key='fetch_gmail'):
        if sender_email and date:
            service = get_gmail_service()
            date_str = date.strftime('%Y/%m/%d')
            next_date_str = (date + timedelta(days=1)).strftime('%Y/%m/%d')
            query = f'from:{sender_email} after:{date_str} before:{next_date_str}'
            results = service.users().messages().list(userId='me', q=query).execute()
            messages = results.get('messages', [])

            if not messages:
                st.write('No messages found from this sender on the specified date.')
                st.session_state.gmail_fetched = False
            else:
                st.write(f'Found {len(messages)} messages from {sender_email} on {date}:')

                for msg in messages[::-1]:
                    msg_id = msg['id']
                    message = service.users().messages().get(userId='me', id=msg_id).execute()
                    snippet = message['snippet']
                    subject, message_content = get_message_details(message)
                    
                    st.write('---')
                    st.write(f'Subject: {subject}')
                    st.write(f'Message ID: {msg_id}')
                    st.write(f'Snippet: {snippet}')
                    st.write('Content:')
                    st.markdown(message_content, unsafe_allow_html=True)
                    st.write('---')
                
                st.session_state.gmail_fetched = True
                st.session_state.gmail_content = f"""Subject:{subject}\nContent:{message_content}"""
                
        else:
            st.write('Please enter a sender email address and a date.')
            st.session_state.gmail_fetched = False

def create_message(sender, to, subject, message_text):
    """Create a message for an email."""
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_message(service, user_id, message):
    """Send an email message."""
    try:
        sent_message = service.users().messages().send(userId=user_id, body=message).execute()
        st.write(f"Message sent successfully: {sent_message['id']}")
    except Exception as error:
        st.write(f"An error occurred: {error}")

def gmailsender():
    st.title('Send an Email via Gmail')
    st.write('Enter the details below to send an email.')

    sender_email = st.text_input('Sender Email Address')
    recipient_email = st.text_input('Recipient Email Address')
    subject = st.text_input('Subject')
    message_text = st.text_area('Message',height=500)

    if st.button('Send Email'):
        if sender_email and recipient_email and subject and message_text:
            service = get_gmail_service()
            message = create_message(sender_email, recipient_email, subject, message_text)
            send_message(service, 'me', message)
        else:
            st.write('Please fill out all fields.')

def evaluator(client):
    st.title("Step 1: Upload SOP File")
    uploaded_file = st.file_uploader("Choose a text file", type="txt")

    if uploaded_file is not None:
        sop_content = uploaded_file.read().decode("utf-8")
        st.session_state.sop_uploaded = True
        modify_sop_content = st.text_area("SOP",sop_content, height=300)
        st.session_state.sop_content = modify_sop_content
    else:
        sop_content = st.text_area("SOP", height=300)
    
    if st.button("Insert text"):
        st.session_state.sop_uploaded = True
        st.session_state.sop_content = sop_content

    if st.session_state.sop_uploaded:
        st.title("Step 2: Client request")
        option = st.selectbox("Choose the way you want get client request", ("By typing","By gmail",), index=0, placeholder='Choose an option')
        if option == 'By gmail':
            st.write('Enter the sender email address and the date to fetch your Gmail messages from that sender.')
            sender_email = st.text_input('Sender Email Address', key='sender_email')
            fetch_gmail(sender_email)
        else:
            client_request = st.text_area("Client Request:", height=500)
            if st.button("Insert Request"):
                st.session_state.gmail_content = client_request
                st.session_state.gmail_fetched = True

        if st.session_state.get('gmail_fetched', False):
            st.text_area("Client Gmail content:", st.session_state.gmail_content,height=400, disabled=True)

            st.title("Step 3: Type your content to evaluate")
            user_input = st.text_area("Your content:", height=400)
            if st.button("Evaluate"):
                if len(user_input) < 20:
                    st.error("Insufficient Information")
                else:
                    prompt = f"""
                            As a Quality Analyst, your task is to meticulously evaluate a user's response to a client email 
                            based on our Standard Operating Procedure (SOP) for email communication. The client email outlines 
                            an issue or concern they are experiencing with our product. Your task involves identifying the 
                            specific problem mentioned by the client and ensuring the response adheres to our SOP. 
                            Follow these steps:

                            SOP Content:{st.session_state.sop_content}

                            Client Email:{st.session_state.gmail_content}

                            Evaluation Task:
                            Identify the Client's Issue: Clearly identify the specific problem or concern mentioned by the client in their email.
                            Evaluate Based on SOP Criteria:
                            For each criterion in the SOP, provide a mark (out of 10) with a reason for the score within 25 words.
                            Criteria include based on the SOP guidelines.
                            Provide Constructive Feedback:
                            Offer actionable feedback aimed at improving future responses.
                            Ensure feedback is specific and provides clear examples where applicable.
                            Suggest Alternatives:
                            Suggest better alternatives email content to the current email content which should fully structured mail.
                            Ensure suggestions align with the SOP and address the client's concern effectively.
                        """

                    try:
                        completion = client.chat.completions.create(
                            messages=[
                                {"role": "system", "content": prompt},
                                {"role": "user", "content": user_input}
                            ],
                            model="llama3-8b-8192",
                            temperature=0,
                        )
                        st.session_state.feedback = completion.choices[0].message.content
                        
                        
                        # Call gmailsender() as Step 4
                        
                    except Exception as e:
                        st.error(f"An error occurred: {e}")
            if st.session_state.feedback:
                # Split the feedback into two parts: before and after the suggested alternatives
                feedback_parts = st.session_state.feedback.split("**Suggested Alternatives:**")
                feedback_text = feedback_parts[0].strip()
                suggested_alternatives_text = feedback_parts[1].strip()

                # Further split the suggested alternatives into subject and content
                # Ensuring robust extraction by locating the "Subject:" and "Dear Jane," occurrences
                subject_start = suggested_alternatives_text.find("Subject:")
                subject_end = suggested_alternatives_text.find("\n\n", subject_start)
                subject = suggested_alternatives_text[subject_start + len("Subject:"):subject_end].strip()

                # Extracting the content part, ensuring that it starts right after the subject section
                content_start = subject_end + 2
                content = suggested_alternatives_text[content_start:].strip()

                # Streamlit app layout
                st.title("Client Feedback and Suggested Alternatives")

                # Display feedback text area
                st.subheader("Feedback")
                st.text_area("Feedback Content", feedback_text, height=300)

                # Display suggested alternatives
                st.subheader("Suggested Alternatives")

                st.text_area("Subject", subject, height=100)
                st.text_area("Content", content, height=300)
            if st.button("Step 4: Send Email") or st.session_state.gmail_send:
                st.session_state.gmail_send = True
                gmailsender()

def main():
    if 'sop_uploaded' not in st.session_state:
        st.session_state.sop_uploaded = False
    if 'gmail_fetched' not in st.session_state:
        st.session_state.gmail_fetched = False
    if 'gmail_content' not in st.session_state:
        st.session_state.gmail_content = ""
    if 'gmail_send' not in st.session_state:
        st.session_state.gmail_send = False
    if 'feedback' not in st.session_state:
        st.session_state.feedback = ""

    client = Groq(api_key=st.secrets["API_KEY"])
    option = st.selectbox("Choose the tool", ("Evaluator",), index=None, placeholder='Choose an option')
    if option == "Evaluator":
        evaluator(client)

if __name__ == "__main__":
    main()
