import json
import logging
from pprint import pprint
import requests
import re
from datetime import datetime, timedelta

import jsonschema

import slack_bolt as bolt
from collections import OrderedDict
import slack_sdk.errors

# Set up logging
logger = logging.getLogger("slack.misc")
logger.setLevel(logging.INFO)


def validate(blocks: list, surface: str | None = "modal") -> bool:
    """Validate whether a block list is valid for a given surface type"""

    if surface not in ["modal", "home", "message", "msg"]:
        raise ValueError(f"Invalid surface type: {surface}")
    # We want our own logger for this function
    schemalogger = logging.getLogger("block-kit validator")

    if surface in ["modal", "home"] and len(blocks) > 100:
        schemalogger.error(f"Block list too long {len(blocks)}/100")
        return False
    elif surface in ["message", "msg"] and len(blocks) > 50:
        schemalogger.error(f"Block list too long {len(blocks)}/50")
        return False

    # Recursively search for all fields called "text" and ensure they don't have an empty string
    for block in blocks:
        if not check_for_empty_text(block, schemalogger):
            return False

    # Load the schema from file
    with open("block-kit-schema.json") as f:
        schema = json.load(f)

    try:
        jsonschema.validate(instance=blocks, schema=schema)
    except jsonschema.exceptions.ValidationError as e:  # type: ignore
        schemalogger.error(e)
        return False
    return True


def check_for_empty_text(block: dict, logger: logging.Logger) -> bool:
    """Recursively search for all fields called "text" and ensure they don't have an empty string

    Slack blocks with empty text fields will be kicked back with an error and this isn't caught by the schema used in validate()
    """
    for key, value in block.items():
        if key == "text" and value == "":
            logger.error(f"Empty text field found in block {block}")
            return False
        if isinstance(value, dict):
            if not check_for_empty_text(block=value, logger=logger):
                return False
    return True


def name_mapper(slack_id: str, slack_app: bolt.App) -> str:
    """
    Returns the slack name(s) of a user given their ID
    """

    slack_id = slack_id.strip()

    # Catch edge cases caused by parsing
    if slack_id == "Unknown":
        return "Unknown"
    elif "No one" in slack_id:
        return "No one"
    elif slack_id == "":
        return ""

    # Check if there's multiple IDs
    if "," in slack_id:
        names = []
        for id in slack_id.split(","):
            names.append(name_mapper(id, slack_app))
        return ", ".join(names)

    user_info = slack_app.client.users_info(user=slack_id)

    # Real name is best
    if user_info["user"].get("real_name", None):
        return user_info["user"]["real_name"]

    # Display is okay
    return user_info["user"]["profile"]["display_name"]


def send_dm(
    slack_id: str,
    message: str,
    slack_app: bolt.App,
    blocks: list = [],
    unfurl_links: bool = False,
    unfurl_media: bool = False,
    username: str | None = None,
    photo: str | None = None,
) -> bool:
    """
    Send a direct message to a user including conversation creation
    """

    # Create a conversation
    conversation = slack_app.client.conversations_open(users=[slack_id])
    conversation_id = conversation["channel"]["id"]

    # Photos are currently bugged for DMs
    photo = None

    # Send the message
    try:
        m = slack_app.client.chat_postMessage(
            channel=conversation_id,
            text=message,
            blocks=blocks,
            unfurl_links=unfurl_links,
            unfurl_media=unfurl_media,
            username=username,
            icon_url=photo,
        )

    except slack_sdk.errors.SlackApiError as e:  # type: ignore
        logger.error(f"Failed to send message to {slack_id}")
        logger.error(e)
        return False

    if not m["ok"]:
        logger.error(f"Failed to send message to {slack_id}")
        logger.error(m)
        return False

    logger.info(f"Sent message to {slack_id}")
    return True


def download_file(url: str, config: dict) -> bytes:
    """Download a file from Slack using our token as authentication"""

    file_data = requests.get(
        url=url,
        headers={"Authorization": f"Bearer {config['slack']['bot_token']}"},
    )
    return file_data.content


def loading_button(body: dict) -> dict:
    """Takes the body of a view_submission and returns a constructed view with the appropriate button updated with a loading button"""

    patching_block = body["actions"][0]

    new_blocks = []

    for block in body["view"]["blocks"]:
        if block["block_id"] == patching_block["block_id"]:
            for element in block["elements"]:
                if element["action_id"] == patching_block["action_id"]:
                    element["text"]["text"] += " :spinthinking:"
            new_blocks.append(block)
        else:
            new_blocks.append(block)

    view = {
        "type": "modal",
        "callback_id": body["view"]["callback_id"],
        "title": body["view"]["title"],
        "blocks": new_blocks,
        "clear_on_close": True,
    }

    if body["view"].get("submit"):
        view["submit"] = body["view"]["submit"]
    if body["view"].get("close"):
        view["close"] = body["view"]["close"]

    return view


def parse_rsvps(line: str) -> dict:
    """Parse a line of text into a dictionary of RSVPs"""

    attendees = {}

    # Remove the type of RSVP
    stripped_line = line.split(": ")[-1].split(", ")

    # Strip the formatting from the user IDs
    attending = [re.sub(r"<@|>", "", user) for user in stripped_line if user]

    for user in attending:
        if "+" in user:
            raw_user_info = user.split("+")
            user_info = [raw_user_info[0], int(raw_user_info[1])]

            # If there's a + we need to account for the user as well
            user_info[1] += 1
        else:
            user_info = [user, 1]

        attendees[user_info[0]] = int(user_info[1])

    return attendees


def format_rsvps(attendees: dict) -> str:
    """Format a dictionary of RSVPs into a string for Slack"""

    formatted = ""

    for user, count in attendees.items():
        if count > 1:
            formatted += f"<@{user}>+{count - 1}, "
        else:
            formatted += f"<@{user}>, "

    formatted = formatted[:-2]

    return formatted


def count_rsvps(attendees: dict | None = None, line: str | None = None) -> int:
    """Count the number of RSVPs in a line of text or a dictionary of RSVPs

    If both are provided, the dictionary will be used"""

    if attendees is None and line is None:
        raise ValueError("Either attendees or line must be provided")

    if attendees is not None:
        return sum(attendees.values())

    if line is not None:
        attendees = parse_rsvps(line)
        return sum(attendees.values())

    return 0


def parse_event(blocks: dict) -> dict:
    """Parse a list of Slack blocks into a dictionary of event data"""
    event = {}
    event["rsvps"] = OrderedDict()

    time_pattern = re.compile(r"\^(\d+)\^")

    for block in blocks:
        if block["block_id"] == "title":
            event["title"] = block["text"]["text"].split(" RSVP")[0].strip()
        elif block["block_id"] == "description":
            event["description"] = block["text"]["text"]
            for field in block["fields"]:
                if field["text"].startswith("*When*:"):
                    time_matches = re.search(time_pattern, field["text"])
                    if time_matches:
                        # Convert the epoch time to a datetime object
                        event["start"] = datetime.fromtimestamp(
                            int(time_matches.group(1))
                        )
                elif field["text"].startswith("*RSVP by*:"):
                    time_matches = re.search(time_pattern, field["text"])
                    if time_matches:
                        # Convert the epoch time to a datetime object
                        event["rsvp_deadline"] = datetime.fromtimestamp(
                            int(time_matches.group(1))
                        )
                elif field["text"].startswith("*Host"):
                    event["hosts"] = [
                        user.strip("<>@")
                        for user in field["text"].split(": ")[1].split(", ")
                    ]
                elif field["text"].startswith("*Price*:"):
                    event["price"] = field["text"].split(": ")[1]

            if block.get("accessory"):
                event["image"] = block["accessory"]["image_url"]

        elif block["block_id"].startswith("RSVP_"):
            event["rsvps"][block["block_id"].replace("RSVP_", "")] = parse_rsvps(
                line=block["text"]["text"]
            )

    return event


def create_event_info(event: dict) -> dict:
    """Create a dictionary of event info from an event template seeded with Google Calendar data"""
    event_info = {}

    event_info["title"] = event.get("title", event["calendar_name"])
    event_info["description"] = event.get("description", "Come on down!")
    if event.get("image"):
        event_info["image"] = event["image"]
    if event.get("price"):
        event_info["price"] = event["price"]
    if event.get("hosts"):
        event_info["hosts"] = event["hosts"]

    event_info["rsvp_options"] = OrderedDict()

    for rsvp_type in event.get("rsvp_options", ["Attending"]):
        event_info["rsvp_options"][rsvp_type] = {}

    if event.get("auto_rsvp"):
        event_info["rsvps"][0] = {user: 1 for user in event["auto_rsvp"]}

    event_info["start"] = event["start"] + timedelta(hours=event.get("event_offset", 0))

    if event.get("rsvp_deadline"):
        event_info["rsvp_deadline"] = event_info["start"] - timedelta(
            hours=event.get("rsvp_deadline", 0)
        )
    else:
        event_info["rsvp_deadline"] = event_info["start"]

    event_info["channel"] = event.get(
        "channel_override", config["slack"]["rsvp_channel"]
    )

    if event.get("regulars"):
        event_info["regulars"] = event["regulars"]

    return event_info


with open("config.json") as f:
    config: dict = json.load(f)
