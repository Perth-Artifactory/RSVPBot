import logging
from copy import deepcopy as copy
from datetime import timedelta
from pprint import pprint

from editable_resources import strings
from slack import blocks, misc

# Set up logging
logger = logging.getLogger("slack.block_formatters")


def format_event(event: dict) -> list[dict]:
    """Formats an event dictionary into a list of blocks for display in Slack."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.header)
    block_list = inject_text(block_list=block_list, text=f"{event['title']} RSVP")
    block_list[-1]["block_id"] = "title"
    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(block_list=block_list, text=event["description"])
    block_list[-1]["block_id"] = "description"

    # Construct info fields
    info_fields = []

    if event.get("price"):
        info_fields.append(copy(blocks.field))
        info_fields[-1]["text"] = f"*Price*: {event['price']}"

    info_fields.append(copy(blocks.field))
    # Calculate the start time of the event based on the datetime modified by the event offset

    info_fields[-1]["text"] = (
        f"*When*: <!date^{int(event['start'].timestamp())}^{{time}} {{date_long_pretty}}|{event['start'].strftime('%A, %B %d, %Y %I:%M %p')}>"
    )

    # Some event edits remove the RSVP deadline as a method of setting it to the event start time
    if "rsvp_deadline" not in event:
        event["rsvp_deadline"] = event["start"]

    if event["rsvp_deadline"] != event["start"]:
        info_fields.append(copy(blocks.field))

        info_fields[-1]["text"] = (
            f"*RSVP by*: <!date^{int(event['rsvp_deadline'].timestamp())}^{{time}} {{date_long_pretty}}|{event['rsvp_deadline'].strftime('%A, %B %d, %Y %I:%M %p')}>"
        )

    if event.get("hosts", []) != []:
        if len(event["hosts"]) > 1:
            field_title = "*Hosts*:"
        else:
            field_title = "*Host*:"
        host_string = ""
        for host in event["hosts"]:
            host_string += f"<@{host}>, "
        host_string = host_string[:-2]
        info_fields.append(copy(blocks.field))
        info_fields[-1]["text"] = f"{field_title} {host_string}"

    block_list[-1]["fields"] = info_fields

    if event.get("image"):
        block_list[-1]["accessory"] = copy(blocks.accessory_image)
        block_list[-1]["accessory"]["image_url"] = event["image"]

    block_list = add_block(block_list=block_list, block=blocks.divider)

    # Construct RSVPs
    rsvp_sections = []
    for option in event["rsvp_options"]:
        rsvp_sections = add_block(block_list=rsvp_sections, block=blocks.text)
        rsvp_sections[-1]["block_id"] = f"RSVP_{option}"
        rsvp_sections[-1]["accessory"] = copy(blocks.button)
        rsvp_sections[-1]["accessory"]["text"]["text"] = f"RSVP: {option}"
        rsvp_sections[-1]["accessory"]["value"] = option
        rsvp_sections[-1]["accessory"]["action_id"] = f"rsvp_{option}"

        if event["rsvp_options"][option]:
            attendees = event["rsvp_options"][option]
            rsvp_sections[-1]["text"]["text"] = (
                f"*{option}* ({misc.count_rsvps(attendees=attendees)}): {misc.format_rsvps(attendees=attendees)}"
            )
        else:
            rsvp_sections[-1]["text"]["text"] = f"*{option}* (0): "

    # Add RSVPs to block list
    block_list += rsvp_sections

    block_list = add_block(block_list=block_list, block=blocks.context)
    block_list = inject_text(
        block_list=block_list,
        text=strings.event_footer,
    )

    return block_list


def modal_rsvp_options(ts, attend_type, channel):
    """Format a message to display that the user has already RSVP'd."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(block_list=block_list, text=strings.already_rsvpd)

    block_list = add_block(block_list=block_list, block=blocks.actions)

    block_list[-1]["elements"].append(copy(blocks.button))
    block_list[-1]["elements"][-1]["text"]["text"] = strings.personal_rsvp
    block_list[-1]["elements"][-1]["action_id"] = "other_rsvp"
    block_list[-1]["elements"][-1]["style"] = "primary"
    block_list[-1]["elements"][-1]["value"] = f"{ts}-{attend_type}-{channel}"

    block_list[-1]["elements"].append(copy(blocks.button))
    block_list[-1]["elements"][-1]["text"]["text"] = strings.slack_rsvp
    block_list[-1]["elements"][-1]["action_id"] = "other_slack_rsvp"
    block_list[-1]["elements"][-1]["value"] = f"{ts}-{attend_type}-{channel}-user"

    block_list[-1]["elements"].append(copy(blocks.button))
    block_list[-1]["elements"][-1]["text"]["text"] = strings.remove_rsvp
    block_list[-1]["elements"][-1]["style"] = "danger"
    block_list[-1]["elements"][-1]["action_id"] = "remove_rsvp"
    block_list[-1]["elements"][-1]["value"] = f"{ts}-{attend_type}-{channel}"

    return block_list


def simple_modal_blocks(text: str) -> list[dict]:
    """Format the blocks for a simple modal that displays one block of text."""

    block_list = add_block(block_list=[], block=blocks.text)
    block_list = inject_text(block_list=block_list, text=text)

    return block_list


def format_multi_rsvp_modal():
    """Format a modal to allow the user to RSVP for multiple people."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(
        block_list=block_list,
        text=strings.rsvp_slack_warning,
    )

    block_list = add_block(block_list=block_list, block=blocks.multi_users_select)
    block_list[-1]["element"]["action_id"] = "multi_rsvp"
    block_list[-1]["label"]["text"] = strings.user_select
    block_list[-1]["block_id"] = "multi_rsvp"
    block_list[-1]["element"].pop("placeholder")

    return block_list


def format_admin_prompt(event) -> list[dict]:
    """Format a message to display admin tools."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(
        block_list=block_list,
        text=strings.admin_tools,
    )

    # Add accessory button
    block_list[-1]["accessory"] = copy(blocks.button)
    block_list[-1]["accessory"]["text"]["text"] = "Admin"
    block_list[-1]["accessory"]["value"] = ",".join(event.get("hosts", ["XXX"]))
    block_list[-1]["accessory"]["action_id"] = "admin_event"

    return block_list


def format_edit_event(event: dict, ts: str, channel: str) -> list[dict]:
    """Format the blocks for an event edit modal and pre-populate with provided event data."""

    block_list = []

    # Don't add the top buttons if the event is being created
    if ts == "NEW":
        block_list = add_block(block_list=block_list, block=blocks.text)
        block_list = inject_text(
            block_list=block_list,
            text=strings.create_event,
        )
    else:
        # Edit RSVP button
        block_list = add_block(block_list=block_list, block=blocks.actions)
        block_list[-1]["block_id"] = "edit_rsvp"
        block_list[-1]["elements"].append(copy(blocks.button))
        block_list[-1]["elements"][-1]["text"]["text"] = "Edit RSVPs"
        block_list[-1]["elements"][-1]["action_id"] = "edit_rsvp_modal"
        block_list[-1]["elements"][-1]["value"] = f"{ts}-{channel}"

        # Edit RSVP options button
        block_list[-1]["elements"].append(copy(blocks.button))
        block_list[-1]["elements"][-1]["text"]["text"] = "Edit RSVP Options"
        block_list[-1]["elements"][-1]["action_id"] = "edit_rsvp_options_modal"
        block_list[-1]["elements"][-1]["value"] = f"{ts}-{channel}"

    # Event title
    block_list = add_block(block_list=block_list, block=blocks.text_question)
    block_list[-1]["element"].pop("placeholder")
    block_list[-1]["element"]["initial_value"] = event["title"]
    block_list[-1]["label"]["text"] = "Event Title"
    block_list[-1]["block_id"] = "title"
    block_list[-1]["element"]["action_id"] = "title"

    # Event description
    block_list = add_block(block_list=block_list, block=blocks.text_question)
    block_list[-1]["element"].pop("placeholder")
    block_list[-1]["element"]["initial_value"] = event["description"]
    block_list[-1]["label"]["text"] = "Event Description"
    block_list[-1]["block_id"] = "description"
    block_list[-1]["element"]["action_id"] = "description"
    block_list[-1]["element"]["multiline"] = True

    # Event image
    block_list = add_block(block_list=block_list, block=blocks.text_question)
    block_list[-1]["optional"] = True
    block_list[-1]["label"]["text"] = "Event Image URL"
    block_list[-1]["block_id"] = "image"
    block_list[-1]["element"]["action_id"] = "image"
    if event.get("image"):
        block_list[-1]["element"]["initial_value"] = event["image"]
        block_list[-1]["element"].pop("placeholder")
    else:
        block_list[-1]["element"]["placeholder"]["text"] = (
            "https://example.com/image.png"
        )

    # Price
    block_list = add_block(block_list=block_list, block=blocks.text_question)
    block_list[-1]["optional"] = True
    block_list[-1]["label"]["text"] = "Event Price"
    block_list[-1]["block_id"] = "price"
    block_list[-1]["element"]["action_id"] = "price"
    if event.get("price"):
        block_list[-1]["element"]["initial_value"] = event["price"]
        block_list[-1]["element"].pop("placeholder")
    else:
        block_list[-1]["element"]["placeholder"]["text"] = "A description of the price"

    # Hosts
    block_list = add_block(block_list=block_list, block=blocks.multi_users_select)
    block_list[-1]["element"]["action_id"] = "hosts"
    block_list[-1]["label"]["text"] = "Event Hosts"
    block_list[-1]["block_id"] = "hosts"
    if event.get("hosts"):
        block_list[-1]["element"]["initial_users"] = event["hosts"]
        block_list[-1]["element"].pop("placeholder")
    else:
        block_list[-1]["element"]["placeholder"]["text"] = "A list of event hosts"
    # Add note that event hosts can make changes to the event
    block_list = add_block(block_list=block_list, block=blocks.context)
    block_list[-1]["elements"][0]["text"] = strings.host_can_edit

    # Event start time
    block_list = add_block(block_list=block_list, block=blocks.datetime_select)
    block_list[-1]["element"]["action_id"] = "start"
    block_list[-1]["block_id"] = "start"
    block_list[-1]["element"]["initial_date_time"] = int(event["start"].timestamp())
    block_list[-1]["label"]["text"] = "Event Start Time"
    block_list[-1]["element"].pop("placeholder")

    # Event RSVP deadline
    block_list = add_block(block_list=block_list, block=blocks.datetime_select)
    block_list[-1]["optional"] = True
    block_list[-1]["element"]["action_id"] = "rsvp_deadline"
    block_list[-1]["block_id"] = "rsvp_deadline"
    block_list[-1]["label"]["text"] = "RSVP Deadline"
    if event["rsvp_deadline"] != event["start"]:
        block_list[-1]["element"]["initial_date_time"] = int(
            event["rsvp_deadline"].timestamp()
        )
    block_list[-1]["element"].pop("placeholder")
    block_list = add_block(block_list=block_list, block=blocks.context)
    block_list[-1]["elements"][0]["text"] = "Leave blank to use the event start time"

    return block_list


def format_edit_rsvps(event: dict, ts: str, channel: str) -> list[dict]:
    """Format the blocks for an RSVP edit modal and pre-populate with provided event data."""

    block_list = []

    for option in event["rsvp_options"]:
        block_list = add_block(block_list=block_list, block=blocks.text)
        block_list = inject_text(
            block_list=block_list,
            text=f"{option} ({misc.count_rsvps(attendees=event['rsvp_options'][option])})",
        )
        block_list[-1]["accessory"] = copy(blocks.button)
        block_list[-1]["accessory"]["text"]["text"] = "Add"
        block_list[-1]["accessory"]["style"] = "primary"
        block_list[-1]["accessory"]["action_id"] = "other_slack_rsvp"
        block_list[-1]["accessory"]["value"] = f"{ts}-{option}-{channel}-host"

        for attendee in event["rsvp_options"][option]:
            block_list = add_block(block_list=block_list, block=blocks.text)
            block_list = inject_text(
                block_list=block_list,
                text=f"<@{attendee}>",
            )
            if event["rsvp_options"][option][attendee] > 1:
                block_list[-1]["text"]["text"] += (
                    f"+{event['rsvp_options'][option][attendee] - 1}"
                )
            block_list[-1]["accessory"] = copy(blocks.button)
            block_list[-1]["accessory"]["text"]["text"] = "Remove"
            block_list[-1]["accessory"]["style"] = "danger"
            block_list[-1]["accessory"]["action_id"] = "remove_rsvp_modal"
            block_list[-1]["accessory"]["value"] = f"{ts}-{channel}-{attendee}-{option}"
        block_list = add_block(block_list=block_list, block=blocks.divider)

    # Trim the last divider
    if block_list[-1]["type"] == "divider":
        block_list.pop()

    return block_list


def format_edit_rsvp_options(event: dict, ts: str, channel: str) -> list[dict]:
    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(
        block_list=block_list,
        text=strings.edit_rsvp_options,
    )
    block_list[-1]["accessory"] = copy(blocks.button)
    block_list[-1]["accessory"]["text"]["text"] = "Add option"
    block_list[-1]["accessory"]["style"] = "primary"
    block_list[-1]["accessory"]["action_id"] = "add_rsvp_option"
    block_list[-1]["accessory"]["value"] = f"{ts}-{channel}"

    for option in event["rsvp_options"]:
        block_list = add_block(block_list=block_list, block=blocks.text_question)
        block_list[-1]["element"].pop("placeholder")
        block_list[-1]["element"]["initial_value"] = option
        block_list[-1]["element"]["action_id"] = "rsvp_option"
        block_list[-1]["label"]["text"] = option
        block_list[-1]["block_id"] = f"rsvp_option_{option}"

        block_list = add_block(block_list=block_list, block=blocks.actions)
        block_list[-1]["block_id"] = f"{option}_delete"
        block_list[-1]["elements"].append(copy(blocks.button))
        block_list[-1]["elements"][-1]["text"]["text"] = "Delete option"
        block_list[-1]["elements"][-1]["action_id"] = "delete_rsvp_option"
        block_list[-1]["elements"][-1]["style"] = "danger"
        block_list[-1]["elements"][-1]["value"] = f"{ts}-{option}-{channel}"

        block_list = add_block(block_list=block_list, block=blocks.divider)

    # Trim the last divider
    if block_list[-1]["type"] == "divider":
        block_list.pop()

    return block_list


def format_create_event_modal(channel: str) -> list[dict]:
    """Format the blocks for a modal to create an event"""

    block_list = []
    block_list = add_block(block_list=block_list, block=blocks.channel_select)
    block_list[-1]["element"]["action_id"] = "channel"
    block_list[-1]["label"]["text"] = "Select a channel for your event RSVP"
    block_list[-1]["block_id"] = "channel"
    block_list[-1]["element"].pop("placeholder")
    block_list[-1]["element"]["initial_channel"] = channel

    block_list = add_block(block_list=block_list, block=blocks.context)
    block_list[-1]["elements"][0]["text"] = (
        "Choose wisely! This cannot be changed later."
    )

    return block_list


def format_event_dm(
    event: dict, message: str, event_link: str, rsvp_option: str
) -> list[dict]:
    """Formats an event into a list of blocks for display in a DM."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(block_list=block_list, text=message)

    # Attach fields with event info
    info_fields = []

    info_fields.append(copy(blocks.field))
    info_fields[-1]["text"] = f"*Event*: {event['title']}"
    info_fields.append(copy(blocks.field))
    info_fields[-1]["text"] = (
        f"*When*: <!date^{int(event['start'].timestamp())}^{{time}} {{date_long_pretty}}|{event['start'].strftime('%A, %B %d, %Y %I:%M %p')}>"
    )
    if event["rsvp_deadline"] != event["start"]:
        info_fields.append(copy(blocks.field))
        info_fields[-1]["text"] = (
            f"*Change deadline*: <!date^{int(event['rsvp_deadline'].timestamp())}^{{time}} {{date_long_pretty}}|{event['rsvp_deadline'].strftime('%A, %B %d, %Y %I:%M %p')}>"
        )

    if event.get("price"):
        info_fields.append(copy(blocks.field))
        info_fields[-1]["text"] = f"*Price*: {event['price']}"

    info_fields.append(copy(blocks.field))
    info_fields[-1]["text"] = f"*RSVP type*: {rsvp_option}"

    info_fields.append(copy(blocks.field))
    info_fields[-1]["text"] = f"<{event_link}|*Event details>"

    return block_list


def app_home(user: str, existing_home: list, past_messages: list) -> list[dict]:
    """Format the blocks for the app home tab."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.header)
    block_list = inject_text(block_list=block_list, text=strings.app_home_title)
    block_list[-1]["block_id"] = "title"

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(block_list=block_list, text=strings.app_home_description)
    block_list[-1]["block_id"] = "description"

    # Add create event button as accessory
    block_list[-1]["accessory"] = copy(blocks.button)
    block_list[-1]["accessory"]["text"]["text"] = "Create Event"
    block_list[-1]["accessory"]["value"] = user
    block_list[-1]["accessory"]["action_id"] = "create_event_modal"
    block_list[-1]["accessory"]["style"] = "primary"

    # Process existing events
    home_events = []
    for block in existing_home:
        if block["block_id"].startswith("event_"):
            home_events.append(block)
            block_list.append(block)

    return block_list


def inject_text(block_list: list, text: str) -> list[dict]:
    """Injects text into the last block in the block list and returns the updated list.

    Is aware of most block types and should inject in the appropriate place
    """

    block_list = copy(block_list)
    if block_list[-1]["type"] in ["section", "header", "button"]:
        block_list[-1]["text"]["text"] = text
    elif block_list[-1]["type"] in ["context"]:
        block_list[-1]["elements"][0]["text"] = text
    elif block_list[-1]["type"] == "modal":
        block_list[-1]["title"]["text"] = text
    elif block_list[-1]["type"] == "rich_text":
        block_list[-1]["elements"][0]["elements"][0]["text"] = text

    return block_list


def add_block(block_list: list, block: dict | list) -> list[dict]:
    """Adds a block to the block list and returns the updated list.

    Performs a deep copy to avoid modifying anything in the original list.
    """
    block = copy(block)
    block_list = copy(block_list)
    if isinstance(block, list):
        block_list += block
    elif isinstance(block, dict):
        block_list.append(block)
    else:
        raise ValueError(f"Block must be a dict or list, not {type(block)}")

    if len(block_list) > 100:
        logger.info(f"Block list too long {len(block_list)}/100")

    return block_list


def compress_blocks(block_list: list[dict]) -> list:
    """Compresses a list of blocks by removing dividers"""

    compressed_blocks = []

    # Remove dividers
    for block in block_list:
        if block["type"] != "divider":
            compressed_blocks.append(block)
    logging.debug(f"Blocks reduced from {len(block_list)} to {len(compressed_blocks)}")

    return compressed_blocks


def text_to_options(options: list[str]) -> list[dict]:
    """Convert a list of strings to a list of option dictionaries"""
    if len(options) > 10:
        logger.warning(f"Too many options ({len(options)}). Truncating to 10")
        options = options[:10]

    formatted_options = []
    for option in options:
        description = None
        text = option
        if len(option) > 150:
            logger.warning(
                f"Option '{option}' is too long for value to be set. Truncating to 150 characters ({len(option)})"
            )
            option = option[:150]
        if len(option) > 75:
            logger.warning(
                f"Option '{option}' is too long for display. Splitting over text and description ({len(option)})"
            )
            text = option[:75]
            description = option[75:]
        formatted_options.append(copy(blocks.option))
        formatted_options[-1]["text"]["text"] = text
        if description:
            formatted_options[-1]["description"] = {
                "type": "plain_text",
                "text": description,
                "emoji": True,
            }
        formatted_options[-1]["value"] = option

    return formatted_options
