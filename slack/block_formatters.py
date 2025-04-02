import logging
from copy import deepcopy as copy
from datetime import timedelta
from pprint import pprint
from slack import blocks

# Set up logging
logger = logging.getLogger("slack.block_formatters")


def format_event(event: dict) -> list[dict]:
    """Formats an event dictionary into a list of blocks for display in Slack."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.header)
    block_list = inject_text(block_list=block_list, text=f"{event['title']} RSVP")
    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(
        block_list=block_list, text=event.get("description", "Come on down!")
    )

    # Construct info fields
    info_fields = []

    if event.get("price"):
        info_fields.append(copy(blocks.field))
        info_fields[-1]["text"] = f"*Price*: {event['price']}"

    info_fields.append(copy(blocks.field))
    # Calculate the start time of the event based on the datetime modified by the event offset
    start_time = event["start"] + timedelta(hours=event["event_offset"])

    info_fields[-1]["text"] = (
        f"*When:* <!date^{int(start_time.timestamp())}^{{time}} {{date_long_pretty}}|{start_time.strftime('%A, %B %d, %Y %I:%M %p')}>"
    )

    if event.get("rsvp_deadline"):
        info_fields.append(copy(blocks.field))
        # Calculate the RSVP time
        rsvp_time = start_time - timedelta(hours=event["rsvp_deadline"])

        info_fields[-1]["text"] = (
            f"*RSVP by*: <!date^{int(rsvp_time.timestamp())}^{{time}} {{date_long_pretty}}|{rsvp_time.strftime('%A, %B %d, %Y %I:%M %p')}>"
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
        rsvp_sections[-1]["text"]["text"] = f"*{option}*: "
        rsvp_sections[-1]["block_id"] = f"RSVP_{option}"
        rsvp_sections[-1]["accessory"] = copy(blocks.button)
        rsvp_sections[-1]["accessory"]["text"]["text"] = f"RSVP: {option}"
        rsvp_sections[-1]["accessory"]["value"] = option
        rsvp_sections[-1]["accessory"]["action_id"] = f"rsvp_{option}"

        # Tack on auto RSVP'd users to the first attending option
        if len(rsvp_sections) == 1 and event.get("auto_rsvp", []) != []:
            rsvp_sections[-1]["accessory"]["text"]["text"] += ", ".join(
                [f"<@{user_id}>" for user_id in event["auto_rsvp"]]
            )

    # Add RSVPs to block list
    block_list += rsvp_sections

    block_list = add_block(block_list=block_list, block=blocks.context)
    block_list = inject_text(
        block_list=block_list,
        text="To RSVP for multiple people or remove your RSVP, click the RSVP button a second time!",
    )

    return block_list


def format_already_rsvp(ts, attend_type):
    """Format a message to display that the user has already RSVP'd."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(
        block_list=block_list, text="You have already RSVP'd to this event."
    )

    block_list = add_block(block_list=block_list, block=blocks.actions)

    block_list[-1]["elements"].append(copy(blocks.button))
    block_list[-1]["elements"][-1]["text"]["text"] = "RSVP for a personal guest"
    block_list[-1]["elements"][-1]["action_id"] = "other_rsvp"
    block_list[-1]["elements"][-1]["style"] = "primary"
    block_list[-1]["elements"][-1]["value"] = f"{ts}-{attend_type}"

    block_list[-1]["elements"].append(copy(blocks.button))
    block_list[-1]["elements"][-1]["text"]["text"] = "RSVP for Slack users"
    block_list[-1]["elements"][-1]["action_id"] = "other_slack_rsvp"
    block_list[-1]["elements"][-1]["value"] = f"{ts}-{attend_type}"

    block_list[-1]["elements"].append(copy(blocks.button))
    block_list[-1]["elements"][-1]["text"]["text"] = "Remove RSVP"
    block_list[-1]["elements"][-1]["style"] = "danger"
    block_list[-1]["elements"][-1]["action_id"] = "remove_rsvp"
    block_list[-1]["elements"][-1]["value"] = f"{ts}-{attend_type}"

    block_list[-1]["elements"].append(copy(blocks.button))
    block_list[-1]["elements"][-1]["text"]["text"] = "Close"
    block_list[-1]["elements"][-1]["action_id"] = "nevermind"
    block_list[-1]["elements"][-1]["value"] = f"{ts}-{attend_type}"

    return block_list


def format_multi_rsvp_modal():
    """Format a modal to allow the user to RSVP for multiple people."""

    block_list = []

    block_list = add_block(block_list=block_list, block=blocks.text)
    block_list = inject_text(
        block_list=block_list,
        text="People you RSVP for here will be the *only ones able to remove their RSVP*. You will not be able to remove it for them.",
    )

    block_list = add_block(block_list=block_list, block=blocks.multi_users_select)
    block_list[-1]["element"]["action_id"] = "multi_rsvp"
    block_list[-1]["label"]["text"] = "Select users to RSVP for"
    block_list[-1]["block_id"] = "multi_rsvp"
    block_list[-1]["element"].pop("placeholder")

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
