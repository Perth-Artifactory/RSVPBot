import json
import logging
import sys
from datetime import datetime, timezone, timedelta
from pprint import pprint

from slack_bolt import App
from slack_sdk.errors import SlackApiError

from slack import block_formatters, misc
from editable_resources import strings

# Set up logging
if "--debug" in sys.argv:
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler("app.debug.log", mode="a"),
            logging.StreamHandler(sys.stdout),
        ],
    )
else:
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
manual = False
for arg in sys.argv:
    if "--manual" in arg and "=" in arg:
        manual = True
        event_id = arg.split("=")[1].lower()
        logger.info(f"Manual mode enabled for event ID: {event_id}")
        if event_id not in event_templates:
            logger.error(f"Event ID {event_id} not found in events.json")
            sys.exit(1)

        # Check if a start time has been provided
        for arg in sys.argv:
            if "--start" in arg and "=" in arg:
                start_time_raw = arg.split("=")[1]
                try:
                    start_time = datetime.fromtimestamp(int(start_time_raw))
                    logger.info(f"Start time overridden to {start_time}")
                    break
                except ValueError:
                    logger.error("Invalid start time format. Use epoch time.")
                    sys.exit(1)
        else:
            start_time = datetime.now(timezone.utc) + timedelta(
                days=event_templates[event_id].get("days_before", config["days_before"])
                + 2
            )
            logger.info(
                f"Start time not provided. Using default start time (days_before+2): {start_time}"
            )

        formatted_events = [
            {
                "start": start_time,
                "title": event_templates[event_id]["calendar_name"],
                "days_until": event_templates[event_id].get(
                    "days_before", config["days_before"]
                ),
            }
        ]
        break
else:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError

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
    logger.debug(f"Checking event: {event['title']}")
    # Look for event templates with a title that matches the event
    for template_event_id in event_templates:
        template_event = event_templates[template_event_id]
        if template_event["calendar_name"] == event["title"]:
            logger.debug(f"Found event template: {template_event_id}")
            if (
                template_event.get("days_before", config["days_before"])
                == event["days_until"]
                or manual
            ):
                unconverted_event = template_event
                unconverted_event["start"] = event["start"]

                converted_event = misc.create_event_info(
                    event=unconverted_event,
                )

                blocks = block_formatters.format_event(event=converted_event)

                try:
                    response = app.client.chat_postMessage(
                        channel=converted_event["channel"],
                        blocks=blocks,
                        text=f"RSVP for {converted_event['title']}!",
                    )
                    ts = response.get("ts", "")
                except SlackApiError as e:
                    logger.error(f"Error posting message: {e.response['error']}")
                    logger.error(e.response)
                    pprint(blocks)

                # Send admin tools as reply

                try:
                    r = app.client.chat_postMessage(
                        channel=converted_event["channel"],
                        blocks=block_formatters.format_admin_prompt(
                            event=converted_event
                        ),
                        text="Admin tools",
                        thread_ts=ts,
                    )
                except SlackApiError as e:
                    logger.error(f"Error posting message: {e.response['error']}")
                    logger.error(e.response)

                # Tag any event regulars in a reply to the event post

                if converted_event.get("regulars"):
                    regulars_str = ", ".join(
                        [f"<@{r}>" for r in converted_event["regulars"]]
                    )
                    try:
                        r = app.client.chat_postMessage(
                            channel=converted_event["channel"],
                            text=strings.regular_ping.format(
                                title=converted_event["title"],
                                regulars_str=regulars_str,
                            ),
                            thread_ts=ts,
                        )
                    except SlackApiError as e:
                        logger.error(f"Error posting message: {e.response['error']}")
                        logger.error(e.response)

                # Send RSVP notifications to auto RSVP users
                if converted_event.get("auto_rsvp_users"):
                    permalink = app.client.chat_getPermalink(
                        channel=converted_event["channel"], message_ts=ts
                    ).get("permalink", "")

                    rsvp_option = list(converted_event["rsvp_options"])[0]

                    for auto_user in converted_event["auto_rsvp_users"]:
                        dm_blocks = block_formatters.format_event_dm(
                            event=converted_event,
                            message="You have been auto RSVP'd to an event",
                            event_link=permalink,
                            rsvp_option=rsvp_option,
                        )

                        try:
                            misc.send_dm(
                                slack_id=auto_user,
                                blocks=dm_blocks,
                                message="You have been auto RSVP'd to an event",
                                slack_app=app,
                                metadata={
                                    "event_type": "rsvp_auto",
                                    "event_payload": {
                                        "ts": ts,
                                        "channel": converted_event["channel"],
                                        "rsvp_option": rsvp_option,
                                        "event_time": int(
                                            converted_event["start"].timestamp()
                                        ),
                                    },
                                },
                            )
                        except SlackApiError as e:
                            logger.error(
                                f"Error posting message: {e.response['error']}"
                            )
                            logger.error(e.response)
