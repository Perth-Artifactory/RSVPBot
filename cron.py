import json
import logging
import sys
from datetime import datetime, timezone
from pprint import pprint

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from slack_bolt import App
from slack_sdk.errors import SlackApiError

from slack import block_formatters

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    handlers=[
        logging.FileHandler("app.log", mode="a"),
        logging.StreamHandler(sys.stdout),
    ],
)
# Set urllib3 logging level to INFO to reduce noise when individual modules are set to debug
urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.setLevel(logging.INFO)
# Set slack bolt logging level to INFO to reduce noise when individual modules are set to debug
slack_logger = logging.getLogger("slack")
slack_logger.setLevel(logging.WARN)
setup_logger = logging.getLogger("setup")
logger = logging.getLogger("slack_app")
response_logger = logging.getLogger("response")

setup_logger.info("Application starting")

# Load config
try:
    with open("config.json") as f:
        config: dict = json.load(f)
except FileNotFoundError:
    setup_logger.error("config.json not found")
    sys.exit(1)

# Load event posts
try:
    with open("events.json") as f:
        event_templates: dict = json.load(f)
except FileNotFoundError:
    logger.error("events.json not found")
    sys.exit(1)

# Set up slack client
app = App(token=config["slack"]["bot_token"], logger=slack_logger)

# Retrieve Google Calendar events


creds = Credentials.from_authorized_user_file(
    "token.json", ["https://www.googleapis.com/auth/calendar.readonly"]
)
try:
    service = build("calendar", "v3", credentials=creds)

    # Call the Calendar API
    now = datetime.now(timezone.utc).isoformat()  # 'Z' indicates UTC time
    events_result = (
        service.events()  # type: ignore
        .list(
            calendarId=config["google"]["calendar_id"],
            timeMin=now,
            maxResults=30,
            singleEvents=True,
            orderBy="startTime",
        )
        .execute()
    )
    events = events_result.get("items", [])

    if not events:
        logger.info("No upcoming events found.")
        sys.exit(1)

    # Construct more useful event dict
    formatted_events = []
    for event in events:
        start = event["start"].get("dateTime", event["start"].get("date"))
        end = event["end"].get("dateTime", event["end"].get("date"))
        if "description" not in event:
            event["description"] = ""
        # Add fake hours to all day events
        if len(start) == 10:
            start = start + "T00:00:00+08:00"
        if len(end) == 10:
            end = end + "T00:00:00+08:00"

        # Calculate how many days until the event
        start_datetime = datetime.fromisoformat(start)
        days_until = (start_datetime - datetime.now(timezone.utc)).days

        formatted_events.append(
            {
                "start": datetime.fromisoformat(start),
                "title": event["summary"],
                "days_until": days_until,
            }
        )

except HttpError:
    logger.error("Error retrieving Google Calendar events")
    sys.exit(1)

for event in formatted_events:
    if event["days_until"] == 4:
        # Look for event templates with a title that matches the event
        for template_event_id in event_templates:
            template_event = event_templates[template_event_id]
            if template_event["calendar_name"] == event["title"]:
                sending_event = template_event
                sending_event["start"] = event["start"]
                blocks = block_formatters.format_event(sending_event)
                try:
                    response = app.client.chat_postMessage(
                        channel=config["slack"]["rsvp_channel"],
                        blocks=blocks,
                        text=f"RSVP for {sending_event['title']}!",
                        username="Event RSVPs",
                        icon_emoji=":calendar:",
                    )
                except SlackApiError as e:
                    logger.error(f"Error posting message: {e.response['error']}")
                    logger.error(e.response)
                    pprint(blocks)

                # Tag any event regulars in a reply to the event post

                if sending_event.get("regulars", []):
                    regulars = sending_event["regulars"]
                    regulars_str = ", ".join([f"<@{r}>" for r in regulars])
                    try:
                        r = app.client.chat_postMessage(
                            channel=config["slack"]["rsvp_channel"],
                            text=f"Notifying regular attendees: {regulars_str}\n\nTalk to an event host if you want to be added to this list for future events!",
                            thread_ts=response["ts"],
                        )
                    except SlackApiError as e:
                        logger.error(f"Error posting message: {e.response['error']}")
                        logger.error(e.response)
