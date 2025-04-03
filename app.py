import json
import logging
import re
import sys
from pprint import pprint
from datetime import datetime, timedelta

import requests
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

# Clear channel
clear = False
if clear:
    # Delete all messages in the RSVP channel

    logging.info("Clearing RSVP channel")

    # Initiate a connection with our admin token
    admin_app = App(token=config["slack"]["user_token"])

    logging.info(f"Reconnected to Slack as {admin_app.client.auth_test()['user_id']}")

    deleted = 0

    try:
        response = app.client.conversations_history(
            channel=config["slack"]["rsvp_channel"], limit=1000
        )
        for message in response["messages"]:
            try:
                admin_app.client.chat_delete(
                    channel=config["slack"]["rsvp_channel"], ts=message["ts"]
                )
                deleted += 1
            except SlackApiError as e:
                logger.error(f"Error deleting message: {e.response['error']}")
    except SlackApiError as e:
        logger.error(f"Error getting messages: {e.response['error']}")
        logger.error(e.response)

    logging.info(f"Deleted {deleted} messages")


@app.action(re.compile(r"^rsvp_.*"))
def rsvp(ack, body):
    ack()

    # Parse event data from the post back into a dictionary
    event = misc.parse_event(body["message"]["blocks"])

    denied = False
    if event.get("start"):
        start_time: datetime = event["start"]
        # Check if the event has already started
        if datetime.now() > start_time:
            denied = True
            # Send an ephemeral message to the user
            try:
                app.client.chat_postEphemeral(
                    channel=body["channel"]["id"],
                    user=body["user"]["id"],
                    text=strings.event_started,
                    icon_emoji=":calendar:",
                )
            except SlackApiError as e:
                logger.error(f"Error posting ephemeral message: {e.response['error']}")
    if event.get("rsvp_deadline") and not denied:
        rsvp_time: datetime = event["rsvp_deadline"]
        # Check if the RSVP deadline has passed
        if datetime.now() > rsvp_time:
            denied = True
            # Send an ephemeral message to the user
            try:
                app.client.chat_postEphemeral(
                    channel=body["channel"]["id"],
                    user=body["user"]["id"],
                    text=strings.rsvp_deadline_passed,
                    icon_emoji=":calendar:",
                )
            except SlackApiError as e:
                logger.error(f"Error posting ephemeral message: {e.response['error']}")

    if denied:
        return

    original_message_blocks = body["message"]["blocks"]
    new_message_blocks = []

    # Get the RSVP block the button was attached to
    rsvp_block_id = body["actions"][0]["block_id"]

    for block in original_message_blocks:
        if block.get("block_id") == rsvp_block_id:
            # Get the list of attendees
            attendees = misc.parse_rsvps(line=block["text"]["text"])

            # Get the user who clicked the button
            user = body["user"]["id"]

            # If the user is already attending, send an ephemeral message instead
            if user in attendees:
                logging.info(
                    "User has already RSVP'd, sending ephemeral message options"
                )

                eph_blocks = block_formatters.format_already_rsvp(
                    ts=body["message"]["ts"], attend_type=body["actions"][0]["value"]
                )

                # Send an ephemeral message to the user
                try:
                    app.client.chat_postEphemeral(
                        channel=body["channel"]["id"],
                        user=user,
                        blocks=eph_blocks,
                        text=strings.already_rsvpd,
                        icon_emoji=":calendar:",
                    )
                except SlackApiError as e:
                    logger.error(
                        f"Error posting ephemeral message: {e.response['error']}"
                    )
                    pprint(eph_blocks)

            # If the user is not in attending, add them to the list
            else:
                attendees[user] = 1

            attend_type = body["actions"][0]["value"]
            block["text"]["text"] = (
                f"*{attend_type}* ({misc.count_rsvps(attendees=attendees)}): {misc.format_rsvps(attendees=attendees)}"
            )
            new_message_blocks.append(block)
        else:
            new_message_blocks.append(block)

    # Update the message
    try:
        app.client.chat_update(
            channel=body["channel"]["id"],
            ts=body["message"]["ts"],
            blocks=new_message_blocks,
            text=body["message"]["text"],
            icon_emoji=":calendar:",
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")


@app.action("remove_rsvp")
def remove_rsvp(ack, body, respond):
    ack()
    # Get the info from the button
    ts, attend_type = body["actions"][0]["value"].split("-")

    # Retrieve the actual message we care about
    result = app.client.conversations_history(
        channel=body["channel"]["id"], inclusive=True, oldest=ts, limit=1
    )

    message = result["messages"][0]

    original_message_blocks = message["blocks"]
    new_message_blocks = []
    block_id = f"RSVP_{attend_type}"

    for block in original_message_blocks:
        if block.get("block_id") == block_id:
            attendees = misc.parse_rsvps(line=block["text"]["text"])

            # Get the user who clicked the button
            user = body["user"]["id"]

            # If the user is already attending, remove them from the list
            if user in attendees:
                del attendees[user]

            block["text"]["text"] = (
                f"*{attend_type}* ({misc.count_rsvps(attendees=attendees)}): {misc.format_rsvps(attendees=attendees)}"
            )
            new_message_blocks.append(block)
        else:
            new_message_blocks.append(block)

    # Update the message
    try:
        app.client.chat_update(
            channel=body["channel"]["id"],
            ts=ts,
            blocks=new_message_blocks,
            text=message["text"],
            icon_emoji=":calendar:",
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")

    respond("RSVP removed!")


@app.action("other_rsvp")
def other_rsvp(ack, body, respond):
    ack()
    ts, attend_type = body["actions"][0]["value"].split("-")

    # Retrieve the actual message we care about

    result = app.client.conversations_history(
        channel=body["channel"]["id"], inclusive=True, oldest=ts, limit=1
    )

    message = result["messages"][0]

    original_message_blocks = message["blocks"]
    new_message_blocks = []

    block_id = f"RSVP_{attend_type}"

    for block in original_message_blocks:
        if block.get("block_id") == block_id:
            attendees = misc.parse_rsvps(line=block["text"]["text"])

            # Get the user who clicked the button
            user = body["user"]["id"]

            if user in attendees:
                attendees[user] += 1
            else:
                attendees[user] = 1

            block["text"]["text"] = (
                f"*{attend_type}* ({misc.count_rsvps(attendees=attendees)}): {misc.format_rsvps(attendees=attendees)}"
            )
            new_message_blocks.append(block)
        else:
            new_message_blocks.append(block)

    # Update the message

    try:
        app.client.chat_update(
            channel=body["channel"]["id"],
            ts=ts,
            blocks=new_message_blocks,
            text=message["text"],
            icon_emoji=":calendar:",
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")

    respond("RSVP added!")


@app.action("other_slack_rsvp")
def modal_other_slack_rsvp(ack, body, respond):
    ack()

    # Delete the original message via the response_url
    try:
        requests.post(body["response_url"], json={"delete_original": True})
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deleting original message: {e}")

    blocks = block_formatters.format_multi_rsvp_modal()
    try:
        app.client.views_open(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "multi_rsvp",
                "title": {"type": "plain_text", "text": "RSVP for others"},
                "blocks": blocks,
                "submit": {"type": "plain_text", "text": "RSVP"},
                "close": {"type": "plain_text", "text": "Cancel"},
                "private_metadata": f"{body['actions'][0]['value']}-{body['channel']['id']}",
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

    # Retrieve the actual message we care about
    result = app.client.conversations_history(
        channel=channel, inclusive=True, oldest=ts, limit=1
    )

    message = result["messages"][0]

    original_message_blocks = message["blocks"]
    new_message_blocks = []
    block_id = f"RSVP_{attend_type}"

    other_attendees = body["view"]["state"]["values"]["multi_rsvp"]["multi_rsvp"][
        "selected_users"
    ]

    added = []

    for block in original_message_blocks:
        if block.get("block_id") == block_id:
            attendees = misc.parse_rsvps(line=block["text"]["text"])

            for new_attendee in other_attendees:
                if new_attendee not in attendees:
                    attendees[new_attendee] = 1
                    added.append(new_attendee)

            block["text"]["text"] = (
                f"*{attend_type}* ({misc.count_rsvps(attendees=attendees)}): {misc.format_rsvps(attendees=attendees)}"
            )
            new_message_blocks.append(block)
        else:
            new_message_blocks.append(block)

    # Update the message
    try:
        app.client.chat_update(
            channel=channel,
            ts=ts,
            blocks=new_message_blocks,
            text=message["text"],
            icon_emoji=":calendar:",
        )
    except SlackApiError as e:
        logger.error(f"Error updating message: {e.response['error']}")

    # Post a new ephemeral message to the user
    eph_message = f"RSVP added for: {', '.join([f'<@{user_id}>' for user_id in added])}"
    if len(added) == 0:
        eph_message = strings.no_rsvps_added
    try:
        app.client.chat_postEphemeral(
            channel=channel,
            user=user,
            text=eph_message,
            icon_emoji=":calendar:",
        )
    except SlackApiError as e:
        logger.error(f"Error posting ephemeral message: {e.response['error']}")

    # Attach an audit message to the original message
    try:
        app.client.chat_postMessage(
            channel=channel,
            thread_ts=ts,
            text=f"{', '.join([f'<@{user_id}>' for user_id in added])} RSVP'd as {attend_type} by <@{user}>",
            icon_emoji=":calendar:",
        )
    except SlackApiError as e:
        logger.error(f"Error posting message: {e.response['error']}")


@app.action("admin_event")
def admin_event(ack, body):
    ack()
    # Delete the original message via the response_url

    # Get the original message this message was replied to
    ts = body["container"]["thread_ts"]

    message = app.client.conversations_history(
        channel=body["channel"]["id"], inclusive=True, oldest=ts, limit=1
    )
    message = message["messages"][0]

    # Get event data
    pprint(message["blocks"])
    event = misc.parse_event(message["blocks"])
    pprint(event)


@app.action("nevermind")
def close_eph(ack, body):
    ack()
    try:
        requests.post(body["response_url"], json={"delete_original": True})
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deleting original message: {e}")


# Start the app
if __name__ == "__main__":
    handler = SocketModeHandler(app, config["slack"]["app_token"])
    handler.start()
