import json
import logging
import re
from collections import OrderedDict
from datetime import datetime, timedelta
from pprint import pprint

import jsonschema
import requests
import slack_bolt as bolt
import slack_sdk.errors
from slack_sdk.errors import SlackApiError
import time

from slack_sdk.web.slack_response import SlackResponse

from slack import block_formatters

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

    user_info: SlackResponse = slack_app.client.users_info(user=slack_id)

    # Real name is best
    if user_info["user"].get("real_name", None):  # type: ignore
        return user_info["user"].get("real_name", "")  # type: ignore

    # Display is okay
    return user_info["user"]["profile"]["display_name"]  # type: ignore


def send_dm(
    slack_id: str,
    message: str,
    slack_app: bolt.App,
    blocks: list = [],
    unfurl_links: bool = False,
    unfurl_media: bool = False,
    username: str | None = None,
    photo: str | None = None,
    metadata: dict | None = None,
) -> bool | str:
    """
    Send a direct message to a user including conversation creation

    Returns the conversation ID of the DM channel if successful, otherwise False
    """

    # Create a conversation
    try:
        conversation = slack_app.client.conversations_open(users=[slack_id])
    except slack_sdk.errors.SlackApiError as e:
        logger.error(f"Failed to open conversation with {slack_id}")
        logger.error(e)
        return False

    conversation_id = conversation["channel"]["id"]  # type: ignore

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
            metadata=metadata,
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
    return m["channel"]  # type: ignore


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
    event["rsvp_options"] = OrderedDict()

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
            event["rsvp_options"][block["block_id"].replace("RSVP_", "")] = parse_rsvps(
                line=block["text"]["text"]
            )
    if "rsvp_deadline" not in event:
        event["rsvp_deadline"] = event["start"]

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

    # We can get the first item in the ordered dict by converting it to a list
    if event.get("auto_rsvp"):
        event_info["rsvp_options"][list(event_info["rsvp_options"])[0]] = {
            user: 1 for user in event["auto_rsvp"]
        }

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


def extract_events_from_dms(
    messages: list,
    bot_id: str,
    slack_app: bolt.App,
    user_id: str,
    compressed: bool = False,
) -> list:
    """Extract events from a list of messages

    Injects the permalink and selected RSVP option(s) into the event data.
    If compressed is True, will collect just the ts/channel/event_time data for all known events."""
    event_changes = {}

    for message in messages:
        if message["user"] == bot_id:
            event_ts = message["metadata"]["event_payload"].get("ts")
            if not event_ts:
                continue
            if event_ts not in event_changes:
                event_changes[event_ts] = []

            event_changes[event_ts].append(
                {
                    "timestamp": message["ts"].split(".")[0],
                    "data": message["metadata"]["event_payload"],
                    "type": message["metadata"]["event_type"],
                }
            )
            event_changes[event_ts][-1]["data"]["event_type"] = message["metadata"][
                "event_type"
            ]

    events_to_retrieve = []
    compressed_events = []

    for event in event_changes:
        if compressed:
            compressed_events.append(
                {
                    "ts": event,
                    "channel": event_changes[event][-1]["data"]["channel"],
                    "event_time": event_changes[event][-1]["data"]["event_time"],
                }
            )
            continue

        last_known_event_timestamp = event_changes[event][-1]["data"]["event_time"]
        last_known_event_date = datetime.fromtimestamp(last_known_event_timestamp)

        # If the event is more than one day in the past, ignore it
        if last_known_event_date < datetime.now() - timedelta(days=1):
            continue

        # Check for RSVP removal events
        if "remove" in event_changes[event][-1]["data"]["event_type"]:
            continue

        events_to_retrieve.append(
            {"ts": event, "channel": event_changes[event][-1]["data"]["channel"]}
        )

    if compressed:
        return compressed_events

    # Sort the events by timestamp
    events_to_retrieve.sort(key=lambda x: x["ts"])

    events = []

    for event in events_to_retrieve:
        message = slack_app.client.conversations_history(
            channel=event["channel"],
            oldest=event["ts"],
            limit=1,
            inclusive=True,
        ).get("messages", [])[0]

        if not message or not message.get("blocks"):
            continue

        # Extract the event data from the message

        event_data = parse_event(message["blocks"])

        # Unlike other event data packages this one is primarily used for home generation
        # We retrieve the permalink and selected rsvp here to make the app home code cleaner

        permalink = slack_app.client.chat_getPermalink(
            channel=event["channel"], message_ts=event["ts"]
        )["permalink"]
        event_data["link"] = permalink

        selected_rsvp = []

        for rsvp_option in event_data["rsvp_options"]:
            if user_id in event_data["rsvp_options"][rsvp_option]:
                selected_rsvp.append(rsvp_option)

        event_data["selected_rsvp"] = ", ".join(selected_rsvp)

        events.append(event_data)

    return events


def update_home(
    user_id: str,
    bot_id: str,
    slack_app: bolt.App,
    silent: bool = False,
    limited: bool = False,
) -> None:
    """Updates the home tab for a user"""

    wait = 2 if not limited else 10

    # Get our DM with the user
    try:
        dm_channel = slack_app.client.conversations_open(users=user_id)
        dm_channel_id: str = dm_channel["channel"]["id"]  # type: ignore
    except SlackApiError as e:
        if e.response["error"] == "ratelimited":
            logger.info(f"Rate limited, retrying in {wait} seconds")
            time.sleep(wait)
            return update_home(user_id, bot_id, slack_app, silent, True)

        logger.error(f"Error opening DM: {e.response['error']}")
        logger.error(e.response)

    # Get all messages from the dm
    try:
        messages = slack_app.client.conversations_history(
            channel=dm_channel_id, limit=999, include_all_metadata=True
        ).get("messages", [])

        events = extract_events_from_dms(
            messages=messages, bot_id=bot_id, slack_app=slack_app, user_id=user_id
        )
    except SlackApiError as e:
        if e.response["error"] == "ratelimited":
            logger.info(f"Rate limited, retrying in {wait} seconds")
            time.sleep(wait)
            return update_home(user_id, bot_id, slack_app, silent, True)

        logger.error(f"Error retrieving messages: {e.response['error']}")
        logger.error(e.response)

    if not silent:
        logger.info(f"Updating home tab for {user_id}")
    try:
        home_blocks = block_formatters.app_home(
            user=user_id,
            events=events,
        )
        slack_app.client.views_publish(
            user_id=user_id,
            view={"type": "home", "callback_id": "home", "blocks": home_blocks},
        )

    except SlackApiError as e:
        if e.response["error"] == "ratelimited":
            logger.info(f"Rate limited, retrying in {wait} seconds")
            time.sleep(wait)
            return update_home(user_id, bot_id, slack_app, silent, True)

        logger.error(f"Error publishing home tab: {e.response['error']}")
        logger.error(e.response)


def get_users(slack_app: bolt.App) -> list:
    """Get a list of users in the workspace

    Returns user IDs not user objects"""

    slack_response = slack_app.client.users_list()
    slack_users = []
    while slack_response.data.get("response_metadata", {}).get("next_cursor"):  # type: ignore
        slack_users += slack_response.data["members"]  # type: ignore
        slack_response = slack_app.client.users_list(
            cursor=slack_response.data["response_metadata"]["next_cursor"]  # type: ignore
        )
    slack_users += slack_response.data["members"]  # type: ignore

    users = []

    # Convert slack response to list of users since it comes as an odd iterable
    for user in slack_users:
        if user["is_bot"] or user["deleted"] or user["id"] == "USLACKBOT":
            continue
        users.append(user["id"])

    return users


def get_dms(
    user_id: str,
    bot_id: str,
    slack_app: bolt.App,
    silent: bool = False,
    limited: bool = False,
) -> list | None:
    """Get our DMs with a user"""

    wait = 2
    if limited:
        wait = 10

    # Get our DM with the user
    try:
        dm_channel = slack_app.client.conversations_open(users=user_id)
        dm_channel_id: str = dm_channel["channel"]["id"]  # type: ignore
    except SlackApiError as e:
        if e.response["error"] == "ratelimited":
            logger.info(f"Rate limited, retrying in {wait} seconds")
            time.sleep(wait)
            return get_dms(
                user_id=user_id,
                bot_id=bot_id,
                slack_app=slack_app,
                silent=silent,
                limited=True,
            )

        logger.error(f"Error opening DM: {e.response['error']}")
        logger.error(e.response)

    # Get all messages from the dm
    try:
        messages = slack_app.client.conversations_history(
            channel=dm_channel_id, limit=999, include_all_metadata=True
        )["messages"]

        return messages

    except SlackApiError as e:
        if e.response["error"] == "ratelimited":
            logger.info(f"Rate limited, retrying in {wait} seconds")
            time.sleep(wait)
            return get_dms(
                user_id=user_id,
                bot_id=bot_id,
                slack_app=slack_app,
                silent=silent,
                limited=True,
            )

        logger.error(f"Error retrieving messages: {e.response['error']}")
        logger.error(e.response)


def extract_event_data_from_pointer(
    slack_app: bolt.App, ts: str, channel: str
) -> tuple[dict, dict]:
    """Extract event data from a ts/channel"""

    # Get the message data from the pointer
    try:
        message = slack_app.client.conversations_history(
            channel=channel,
            limit=1,
            inclusive=True,
            oldest=ts,
        ).get("messages", [])[0]

        parsed_event: dict = parse_event(message["blocks"])

        return parsed_event, message

    except SlackApiError as e:
        logger.error(f"Error retrieving message: {e.response['error']}")
        logger.error(e.response)
    except IndexError:
        logger.error("Error retrieving message")

    return {}, {}


def get_events_from_user(user_id: str, bot_id: str, slack_app: bolt.App) -> list:
    """Get all events from a user"""

    # Get all DMs with the user
    messages = get_dms(
        user_id=user_id, bot_id=bot_id, slack_app=slack_app, limited=True
    )

    if not messages:
        return []

    # Extract events from the DMs
    events = extract_events_from_dms(
        messages=messages,
        bot_id=bot_id,
        slack_app=slack_app,
        user_id=user_id,
        compressed=True,
    )

    return events


def delete_event(slack_app: bolt.App, channel: str, ts: str) -> bool:
    """Delete an event from a channel"""

    # Get all replies to the event post

    try:
        replies = slack_app.client.conversations_replies(
            channel=channel,
            ts=ts,
            limit=1000,
        ).get("messages", [])
    except SlackApiError as e:
        logger.error(f"Error retrieving replies: {e.response['error']}")
        logger.error(e.response)
        return False

    # Delete the replies
    for reply in replies:
        try:
            slack_app.client.chat_delete(
                channel=channel,
                ts=reply["ts"],
            )
        except SlackApiError as e:
            logger.error(f"Error deleting reply: {e.response['error']}")
            logger.error(e.response)
            return False
    # Delete the original message
    try:
        slack_app.client.chat_delete(
            channel=channel,
            ts=ts,
        )
    except SlackApiError as e:
        if e.response["error"] != "message_not_found":
            logger.error(f"Error deleting message: {e.response['error']}")
            logger.error(e.response)
            return False
    return True


with open("config.json") as f:
    config: dict = json.load(f)
