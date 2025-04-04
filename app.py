import json
import logging
import re
import sys
from pprint import pprint
from datetime import datetime

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk.errors import SlackApiError

from slack import block_formatters, misc
from editable_resources import strings


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
    setup_logger.error(
        "config.json not found. Create it using example.config.json as a template"
    )
    sys.exit(1)

# Load event posts
try:
    with open("events.json") as f:
        events: dict = json.load(f)
except FileNotFoundError:
    events = {}

# Set up slack client
app = App(token=config["slack"]["bot_token"], logger=slack_logger)


@app.action(re.compile(r"^rsvp_.*"))
def rsvp(ack, body):
    """Respond to specific RSVP button actions"""
    ack()

    # Parse event data from the post back into a dictionary
    event = misc.parse_event(body["message"]["blocks"])

    denied = False
    if event.get("start"):
        start_time: datetime = event["start"]
        # Check if the event has already started
        if datetime.now() > start_time:
            denied = True
            # Send a notice to the user
            try:
                app.client.views_open(
                    trigger_id=body["trigger_id"],
                    view={
                        "type": "modal",
                        "callback_id": "event_started",
                        "title": {"type": "plain_text", "text": "Event Started"},
                        "blocks": block_formatters.simple_modal_blocks(
                            text=strings.event_started
                        ),
                        "close": {"type": "plain_text", "text": "Close"},
                        "clear_on_close": True,
                    },
                )
            except SlackApiError as e:
                logger.error(f"Error opening modal: {e.response['error']}")
                logger.error(e.response)
    if event.get("rsvp_deadline") and not denied:
        rsvp_time: datetime = event["rsvp_deadline"]
        # Check if the RSVP deadline has passed
        if datetime.now() > rsvp_time:
            denied = True
            # Send a notice to the user
            try:
                app.client.views_open(
                    trigger_id=body["trigger_id"],
                    view={
                        "type": "modal",
                        "callback_id": "rsvp_deadline_passed",
                        "title": {"type": "plain_text", "text": "RSVP Deadline Passed"},
                        "blocks": block_formatters.simple_modal_blocks(
                            text=strings.rsvp_deadline_passed
                        ),
                        "close": {"type": "plain_text", "text": "Close"},
                        "clear_on_close": True,
                    },
                )
            except SlackApiError as e:
                logger.error(f"Error opening modal: {e.response['error']}")
                logger.error(e.response)

    if denied:
        return

    rsvp_option = body["actions"][0]["value"]
    user = body["user"]["id"]

    if user in event["rsvp_options"][rsvp_option]:
        # User is already attending, send them a modal instead
        logging.info("User has already RSVP'd, sending modal with extra options")

        option_blocks = block_formatters.modal_rsvp_options(
            ts=body["message"]["ts"],
            attend_type=rsvp_option,
            channel=body["channel"]["id"],
        )

        # Open a new modal
        try:
            app.client.views_open(
                trigger_id=body["trigger_id"],
                view={
                    "type": "modal",
                    "callback_id": "rsvp_modal",
                    "title": {"type": "plain_text", "text": "RSVP Options"},
                    "blocks": option_blocks,
                    "close": {"type": "plain_text", "text": "Cancel"},
                },
            )
        except SlackApiError as e:
            logger.error(f"Error opening modal: {e.response['error']}")
            logger.error(e.response)

    else:
        event["rsvp_options"][rsvp_option][user] = 1

    # Convert the event back into blocks
    blocks = block_formatters.format_event(event=event)

    # Update the message
    try:
        app.client.chat_update(
            channel=body["channel"]["id"],
            ts=body["message"]["ts"],
            blocks=blocks,
            text=body["message"]["text"],
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")


@app.action("remove_rsvp")
def remove_rsvp(ack, body):
    """Remove the RSVP (if present) for the triggering user"""
    ack()
    # Get the info from the button
    ts, attend_type, channel = body["actions"][0]["value"].split("-")
    user = body["user"]["id"]

    # Retrieve the actual message we care about
    result = app.client.conversations_history(
        channel=channel, inclusive=True, oldest=ts, limit=1
    )

    message = result["messages"][0]

    # Convert the blocks into an event dictionary
    event = misc.parse_event(message["blocks"])

    # Remove the user from the event if they exist
    if user in event["rsvp_options"][attend_type]:
        del event["rsvp_options"][attend_type][user]

    # Convert the event back into blocks
    blocks = block_formatters.format_event(event=event)

    # Update the message
    try:
        app.client.chat_update(
            channel=channel,
            ts=ts,
            blocks=blocks,
            text=message["text"],
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")

    # Push a new modal to the user letting them know their RSVP was removed
    try:
        app.client.views_push(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "rsvp_removed",
                "title": {"type": "plain_text", "text": "RSVP Removed"},
                "blocks": block_formatters.simple_modal_blocks(
                    text=strings.rsvp_removed.format(
                        timestamp=int(event["rsvp_deadline"].timestamp()),
                        time_formatted=event["rsvp_deadline"].strftime(
                            "%A, %B %d, %Y %I:%M %p"
                        ),
                    )
                ),
                "close": {"type": "plain_text", "text": "Close"},
                "clear_on_close": True,
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)


@app.action("other_rsvp")
def other_rsvp(ack, body):
    ack()
    ts, attend_type, channel = body["actions"][0]["value"].split("-")
    user = body["user"]["id"]

    # Retrieve the actual message we care about

    result = app.client.conversations_history(
        channel=channel, inclusive=True, oldest=ts, limit=1
    )

    message = result["messages"][0]

    # Convert the blocks into an event dictionary
    event = misc.parse_event(message["blocks"])

    # Increase the count of the user or add them if they don't exist
    if user in event["rsvp_options"][attend_type]:
        event["rsvp_options"][attend_type][user] += 1
    else:
        event["rsvp_options"][attend_type][user] = 1

    # Convert the event back into blocks
    blocks = block_formatters.format_event(event=event)

    # Update the message
    try:
        app.client.chat_update(
            channel=channel,
            ts=ts,
            blocks=blocks,
            text=message["text"],
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")

    # Push a new modal to the user letting them know their RSVP was added
    try:
        app.client.views_push(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "rsvp_added",
                "title": {"type": "plain_text", "text": "RSVP Added"},
                "blocks": block_formatters.simple_modal_blocks(
                    text=strings.rsvp_added.format(
                        rsvp_count=event["rsvp_options"][attend_type][user]
                    )
                ),
                "close": {"type": "plain_text", "text": "Close"},
                "clear_on_close": True,
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)


@app.action("other_slack_rsvp")
def modal_other_slack_rsvp(ack, body):
    ack()

    blocks = block_formatters.format_multi_rsvp_modal()
    try:
        app.client.views_push(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "multi_rsvp",
                "title": {"type": "plain_text", "text": "RSVP for others"},
                "blocks": blocks,
                "submit": {"type": "plain_text", "text": "RSVP"},
                "close": {"type": "plain_text", "text": "Cancel"},
                "private_metadata": body["actions"][0]["value"],
                "clear_on_close": True,
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)
        pprint(blocks)


@app.view("multi_rsvp")
def multi_rsvp_submit(ack, body, logger):
    ack()

    # Parse the private metadata
    ts, attend_type, channel = body["view"]["private_metadata"].split("-")
    user = body["user"]["id"]
    other_attendees = body["view"]["state"]["values"]["multi_rsvp"]["multi_rsvp"][
        "selected_users"
    ]

    # Retrieve the actual message we care about
    result = app.client.conversations_history(
        channel=channel, inclusive=True, oldest=ts, limit=1
    )

    message = result["messages"][0]

    # Convert the blocks into an event dictionary
    event = misc.parse_event(message["blocks"])

    # Add users to the event if they have not already RSVP'd, do nothing if they have
    added = []
    not_added = []
    for prospective_attendee in other_attendees:
        if prospective_attendee not in event["rsvp_options"][attend_type]:
            event["rsvp_options"][attend_type][prospective_attendee] = 1
            added.append(prospective_attendee)
        else:
            not_added.append(prospective_attendee)

    # Convert the event back into blocks
    blocks = block_formatters.format_event(event=event)

    # Update the message
    try:
        app.client.chat_update(
            channel=channel,
            ts=ts,
            blocks=blocks,
            text=message["text"],
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")

    # Push a new modal to the user letting them know their RSVP was removed
    modal_text = ""
    if added:
        modal_text = strings.rsvp_slack_added.format(
            user_plural="users have" if len(added) > 1 else "user has",
            user_list=", ".join([f"<@{user_id}>" for user_id in added]),
        )

    if not_added:
        modal_text += "\n" + strings.rsvp_slack_not_added.format(
            user_plural="users were" if len(not_added) > 1 else "user was",
            user_list=", ".join([f"<@{user_id}>" for user_id in not_added]),
        )

    try:
        app.client.views_update(
            view_id=body["view"]["previous_view_id"],
            view={
                "type": "modal",
                "callback_id": "rsvp_added",
                "title": {"type": "plain_text", "text": "RSVP Added"},
                "blocks": block_formatters.simple_modal_blocks(text=modal_text),
                "close": {"type": "plain_text", "text": "Close"},
                "clear_on_close": True,
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)

    # Attach an audit message to the original message
    try:
        app.client.chat_postMessage(
            channel=channel,
            thread_ts=ts,
            text=f"{', '.join([f'<@{user_id}>' for user_id in added])} RSVP'd as {attend_type} by <@{user}>",
        )
    except SlackApiError as e:
        logger.error(f"Error posting message: {e.response['error']}")


@app.action("admin_event")
def admin_event(ack, body):
    ack()

    # Get the original message this message was replied to
    ts = body["container"]["thread_ts"]
    user = body["user"]["id"]

    message = app.client.conversations_history(
        channel=body["channel"]["id"], inclusive=True, oldest=ts, limit=1
    )
    message = message["messages"][0]

    # Get event data
    event = misc.parse_event(message["blocks"])

    # Check if the user is an event host
    if user in event.get("hosts", []):
        blocks = block_formatters.format_edit_event(event=event)
        # User is an event host, send them a modal with the event data
        try:
            app.client.views_open(
                trigger_id=body["trigger_id"],
                view={
                    "type": "modal",
                    "callback_id": "write_edit_event",
                    "title": {"type": "plain_text", "text": "Edit event"},
                    "blocks": blocks,
                    "close": {"type": "plain_text", "text": "Cancel"},
                    "submit": {"type": "plain_text", "text": "Save"},
                    "private_metadata": f"{ts}-{body['channel']['id']}",
                    "clear_on_close": True,
                },
            )
        except SlackApiError as e:
            logger.error(f"Error opening modal: {e.response['error']}")
            logger.error(e.response)
    else:
        # User is not an event host, send them a modal with the event data
        try:
            app.client.views_open(
                trigger_id=body["trigger_id"],
                view={
                    "type": "modal",
                    "callback_id": "not_event_host",
                    "title": {"type": "plain_text", "text": "Not an Event Host"},
                    "blocks": block_formatters.simple_modal_blocks(
                        text=strings.not_host
                    ),
                    "close": {"type": "plain_text", "text": "Close"},
                    "clear_on_close": True,
                },
            )
        except SlackApiError as e:
            logger.error(f"Error opening modal: {e.response['error']}")
            logger.error(e.response)


@app.view("write_edit_event")
def write_edit_event(ack, body):
    """Handle the event edit modal submission"""
    ack()

    ts, channel = body["view"]["private_metadata"].split("-")
    user = body["user"]["id"]

    # Get a fresh copy of the event message
    message = app.client.conversations_history(
        channel=channel, inclusive=True, oldest=ts, limit=1
    )
    message = message["messages"][0]

    # Parse the event data from the message
    event = misc.parse_event(message["blocks"])

    # Get the new event data from the modal
    for key in body["view"]["state"]["values"]:
        data = body["view"]["state"]["values"][key][key]
        if data["type"] == "plain_text_input":
            event[key] = data["value"]
        elif data["type"] == "multi_users_select":
            event[key] = data["selected_users"]
        elif data["type"] == "datetimepicker":
            event[key] = datetime.fromtimestamp(data["selected_date_time"])

    # Convert the event back into blocks
    blocks = block_formatters.format_event(event=event)

    # Update the message
    try:
        app.client.chat_update(
            channel=channel,
            ts=ts,
            blocks=blocks,
            text=message["text"],
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")
        logger.error(e.response)


# Start the app
if __name__ == "__main__":
    handler = SocketModeHandler(app, config["slack"]["app_token"])
    handler.start()
