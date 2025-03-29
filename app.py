import json
import logging
import re
import sys
from pprint import pprint

import requests
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
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

# Send demo messages
posting = False
if posting:
    for event_id in events:
        event = events[event_id]
        blocks = block_formatters.format_event(event)
        try:
            app.client.chat_postMessage(
                channel=config["slack"]["rsvp_channel"],
                blocks=blocks,
                text=f"RSVP for {event['title']}!",
                icon_emoji=":calendar:",
            )
        except SlackApiError as e:
            logger.error(f"Error posting message: {e.response['error']}")
            pprint(blocks)


@app.action(re.compile(r"^rsvp_.*"))
def rsvp(ack, body):
    ack()

    original_message_blocks = body["message"]["blocks"]
    new_message_blocks = []

    # Get the RSVP block the button was attached to
    rsvp_block_id = body["actions"][0]["block_id"]

    for block in original_message_blocks:
        if block.get("block_id") == rsvp_block_id:
            # Parse out who is attending right now
            attending_raw = block["text"]["text"]
            attending_formatted = attending_raw.split(": ")[1].split(", ")
            # Strip the formatting from the user IDs
            attending = [
                re.sub(r"<@|>", "", user) for user in attending_formatted if user
            ]
            # Get the user who clicked the button
            user = body["user"]["id"]
            # If the user is already attending, send an ephemeral message instead
            # We use attending_raw instead of attending so we don't need to handle +1s
            if user in attending_raw:
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
                        text="You have already RSVP'd to this event.",
                        icon_emoji=":calendar:",
                    )
                except SlackApiError as e:
                    logger.error(
                        f"Error posting ephemeral message: {e.response['error']}"
                    )
                    pprint(eph_blocks)

            # If the user is not in attending, add them to the list
            else:
                attending.append(user)

            # Reformat the attending list
            attending_formatted = []
            for user in attending:
                if "+" in user:
                    user_info = user.split("+")
                    attending_formatted.append(f"<@{user_info[0]}>+{user_info[1]}")
                else:
                    attending_formatted.append(f"<@{user}>")
            attending_count = len(attending_formatted)
            attending_formatted = ", ".join(attending_formatted)
            block["text"]["text"] = (
                f"*{body['actions'][0]['value']}* ({attending_count}): {attending_formatted}"
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
            attending_raw = block["text"]["text"]
            attending_formatted = attending_raw.split(": ")[1].split(", ")
            attending = [
                re.sub(r"<@|>", "", user) for user in attending_formatted if user
            ]
            user = body["user"]["id"]
            attending_formatted = []
            for attendee in attending:
                if user in attendee:
                    continue
                else:
                    if "+" in attendee:
                        user_info = attendee.split("+")
                        attending_formatted.append(f"<@{user_info[0]}>+{user_info[1]}")
                    else:
                        attending_formatted.append(f"<@{attendee}>")
            attending_count = len(attending_formatted)
            attending_formatted = ", ".join(attending_formatted)
            block["text"]["text"] = (
                f"*{attend_type}* ({attending_count}): {attending_formatted}"
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
    user = body["user"]["id"]

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
            attending_raw = block["text"]["text"]
            attending_formatted = attending_raw.split(": ")[1].split(", ")
            attending = [
                re.sub(r"<@|>", "", user) for user in attending_formatted if user
            ]
            new_attending_formatted = []
            for attendee in attending:
                if user in attendee:
                    if "+" in attendee:
                        count = int(attendee.split("+")[1])
                        new_attending_formatted.append(f"<@{user}>+{count + 1}")
                    else:
                        new_attending_formatted.append(f"<@{user}>+1")
                else:
                    if "+" in attendee:
                        user_info = attendee.split("+")
                        new_attending_formatted.append(
                            f"<@{user_info[0]}>+{user_info[1]}"
                        )
                    else:
                        new_attending_formatted.append(f"<@{attendee}>")
            attending_count = len(new_attending_formatted)
            attending_formatted = ", ".join(new_attending_formatted)
            block["text"]["text"] = (
                f"*{attend_type}* ({attending_count}): {attending_formatted}"
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
            attending_raw = block["text"]["text"]
            attending_formatted = attending_raw.split(": ")[1].split(", ")
            attending = [
                re.sub(r"<@|>", "", user) for user in attending_formatted if user
            ]
            attending_formatted = []
            for new_attendee in other_attendees:
                already_attending = False
                for attendee in attending:
                    if new_attendee in attendee:
                        already_attending = True
                        break
                if not already_attending:
                    attending.append(new_attendee)
                    added.append(new_attendee)
            for attendee in attending:
                if "+" in attendee:
                    attendee_info = attendee.split("+")
                    attending_formatted.append(
                        f"<@{attendee_info[0]}>+{attendee_info[1]}"
                    )
                else:
                    attending_formatted.append(f"<@{attendee}>")
            attending_count = len(attending_formatted)
            attending_formatted = ", ".join(attending_formatted)
            block["text"]["text"] = (
                f"*{attend_type}* ({attending_count}): {attending_formatted}"
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
        eph_message = "No new RSVPs added (they may already be attending)"
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
