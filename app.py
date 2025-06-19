import json
import logging
import re
import sys
from pprint import pprint
from datetime import datetime, timedelta

from slack_bolt.context.ack.ack import Ack as slack_ack
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk.errors import SlackApiError
from slack_sdk.web.slack_response import SlackResponse

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
def rsvp(ack: slack_ack, body: dict) -> None:
    """Respond to specific RSVP button actions"""
    ack()

    channel = body["channel"]["id"]
    ts = body["message"]["ts"]
    rsvp_option = body["actions"][0]["value"]
    user = body["user"]["id"]

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

    if config["slack"]["member_status_emoji"] in rsvp_option and not denied:
        # Get the status of the member
        try:
            user_info = app.client.users_info(user=user)

            user_status = (
                user_info.get("user", {}).get("profile", {}).get("status_emoji", "")
            )

            # Remove : from the user status
            user_status.replace(":", "")

            if user_status != config["slack"]["member_status_emoji"]:
                denied = True

                # Let the user know
                app.client.views_open(
                    trigger_id=body["trigger_id"],
                    view={
                        "type": "modal",
                        "callback_id": "members_only_rsvp",
                        "title": {"type": "plain_text", "text": "Members only"},
                        "blocks": block_formatters.simple_modal_blocks(
                            text=strings.members_only_rsvp
                        ),
                        "close": {"type": "plain_text", "text": "Close"},
                        "clear_on_close": True,
                    },
                )
        except SlackApiError as e:
            logger.error(f"Error getting user info: {e.response['error']}")
            logger.error(e.response)

    if denied:
        return

    if user in event["rsvp_options"][rsvp_option]:
        # User is already attending, send them a modal instead
        logging.info("User has already RSVP'd, sending modal with extra options")

        option_blocks = block_formatters.modal_rsvp_options(
            ts=ts,
            attend_type=rsvp_option,
            channel=channel,
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
                channel=channel,
                ts=ts,
                blocks=blocks,
                text=body["message"]["text"],
            )
        except SlackApiError as e:
            logger.error(f"Error updating message: {e.response['error']}")

        # Get a permalink to the message
        try:
            permalink = app.client.chat_getPermalink(channel=channel, message_ts=ts)[
                "permalink"
            ]
        except SlackApiError as e:
            logger.error(f"Error getting permalink: {e.response['error']}")
            logger.error(e.response)

            # We can't send a useful DM if we don't have a permalink
            return

        assert permalink is not None

        # Send a DM to the user as a record of the RSVP
        dm_blocks = block_formatters.format_event_dm(
            event=event,
            message="You have RSVP'd to an event",
            event_link=permalink,
            rsvp_option=rsvp_option,
        )
        try:
            misc.send_dm(
                slack_id=user,
                message="You have RSVP'd to an event",
                slack_app=app,
                blocks=dm_blocks,
                metadata={
                    "event_type": "rsvp",
                    "event_payload": {
                        "ts": ts,
                        "channel": channel,
                        "rsvp_option": rsvp_option,
                        "event_time": int(event["start"].timestamp()),
                    },
                },
            )
        except SlackApiError as e:
            logger.error(f"Error sending DM: {e.response['error']}")
            logger.error(e.response)


@app.action("remove_rsvp")
def remove_rsvp(ack: slack_ack, body: dict) -> None:
    """Remove the RSVP (if present) for the triggering user"""
    ack()
    # Get the info from the button
    ts, attend_type, channel = body["actions"][0]["value"].split("-")
    user = body["user"]["id"]

    event, message = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

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

    # Get the permalink to the event message
    try:
        permalink = app.client.chat_getPermalink(channel=channel, message_ts=ts)[
            "permalink"
        ]
    except SlackApiError as e:
        logger.error(f"Error getting permalink: {e.response['error']}")
        logger.error(e.response)

        # We can't send a useful DM if we don't have a permalink
        return

    # The only way for permalink to fail is caught by the except block above
    assert permalink is not None

    # Send a DM to the user as a record of the RSVP removal
    dm_blocks = block_formatters.format_event_dm(
        event=event,
        message=strings.notice_rsvp_removed,
        event_link=permalink,
        rsvp_option=attend_type,
    )
    try:
        misc.send_dm(
            slack_id=user,
            message=strings.notice_rsvp_removed,
            slack_app=app,
            blocks=dm_blocks,
            metadata={
                "event_type": "rsvp_removed",
                "event_payload": {
                    "ts": ts,
                    "channel": channel,
                    "rsvp_option": attend_type,
                    "event_time": int(event["start"].timestamp()),
                },
            },
        )
    except SlackApiError as e:
        logger.error(f"Error sending DM: {e.response['error']}")
        logger.error(e.response)


@app.action("remove_rsvp_modal")
def remove_rsvp_modal(ack: slack_ack, body: dict) -> None:
    """Remove the RSVP (if present) for the specified user"""
    ack()
    # Get the info from the button
    ts, channel, user, attend_type = body["actions"][0]["value"].split("-")

    admin = body["user"]["id"]

    event, message = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

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

    # Update the current modal to show the RSVP was removed
    # We update the modal even if we didn't find the attendee because
    # they've removed themselves and we need to update the list
    blocks = block_formatters.format_edit_rsvps(event=event, ts=ts, channel=channel)

    try:
        app.client.views_update(
            view_id=body["view"]["id"],
            view={
                "type": "modal",
                "callback_id": "edit_rsvp_modal",
                "title": {"type": "plain_text", "text": "Edit RSVPs"},
                "blocks": blocks,
                "close": {"type": "plain_text", "text": "Cancel"},
                "private_metadata": f"{ts}-{channel}",
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)

    # Don't spend the time DMing a user until we've finished with the current interaction

    permalink = app.client.chat_getPermalink(channel=channel, message_ts=ts)[
        "permalink"
    ]

    # The only way for permalink to fail is if it was deleted in the milliseconds since we retrieved it above
    assert permalink is not None

    # Send a DM to the user as a record of the RSVP removal
    dm_blocks = block_formatters.format_event_dm(
        event=event,
        message=strings.notice_rsvp_removed,
        event_link=permalink,
        rsvp_option=attend_type,
    )
    try:
        misc.send_dm(
            slack_id=user,
            message=f"Your RSVP to an event has been removed by <@{admin}>",
            slack_app=app,
            blocks=dm_blocks,
            metadata={
                "event_type": "rsvp_removed_admin",
                "event_payload": {
                    "ts": ts,
                    "channel": channel,
                    "rsvp_option": attend_type,
                    "event_time": int(event["start"].timestamp()),
                },
            },
        )
    except SlackApiError as e:
        logger.error(f"Error sending DM: {e.response['error']}")
        logger.error(e.response)


@app.action("other_rsvp")
def other_rsvp(ack: slack_ack, body: dict) -> None:
    ack()
    ts, attend_type, channel = body["actions"][0]["value"].split("-")
    user = body["user"]["id"]

    event, message = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

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

    # Send a DM to the user as a record of the RSVP

    permalink = app.client.chat_getPermalink(channel=channel, message_ts=ts).get(
        "permalink", ""
    )

    dm_blocks = block_formatters.format_event_dm(
        event=event,
        message="You have increased your guest RSVP for an event",
        event_link=permalink,
        rsvp_option=attend_type,
    )

    try:
        misc.send_dm(
            slack_id=user,
            message="You have increased your guest RSVP for an event",
            slack_app=app,
            blocks=dm_blocks,
            metadata={
                "event_type": "rsvp_guest",
                "event_payload": {
                    "ts": ts,
                    "channel": channel,
                    "rsvp_option": attend_type,
                    "event_time": int(event["start"].timestamp()),
                },
            },
        )
    except SlackApiError as e:
        logger.error(f"Error sending DM: {e.response['error']}")
        logger.error(e.response)


@app.action("other_slack_rsvp")
def modal_other_slack_rsvp(ack: slack_ack, body: dict) -> None:
    ack()

    user_type = body["actions"][0]["value"].split("-")[-1]

    blocks = block_formatters.format_multi_rsvp_modal(user_type=user_type)
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
def multi_rsvp_submit(ack: slack_ack, body: dict) -> None:
    ack()

    # Parse the private metadata
    ts, attend_type, channel, usertype = body["view"]["private_metadata"].split("-")

    event, message = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

    user = body["user"]["id"]
    other_attendees = body["view"]["state"]["values"]["multi_rsvp"]["multi_rsvp"][
        "selected_users"
    ]

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

    # Users get a new modal, hosts just get their existing modal updated
    if usertype == "user":
        # Push a new modal to the user letting them know the other user(s) were RSVP'd
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
    elif usertype == "host":
        # Update the current modal to show the RSVP was removed
        blocks = block_formatters.format_edit_rsvps(event=event, ts=ts, channel=channel)

        try:
            app.client.views_update(
                view_id=body["view"]["previous_view_id"],
                view={
                    "type": "modal",
                    "callback_id": "edit_rsvp_modal",
                    "title": {"type": "plain_text", "text": "Edit RSVPs"},
                    "blocks": blocks,
                    "private_metadata": f"{ts}-{channel}",
                },
            )
        except SlackApiError as e:
            logger.error(f"Error opening modal: {e.response['error']}")
            logger.error(e.response)

    # Send a DM to the user as a record of the RSVP

    permalink = app.client.chat_getPermalink(channel=channel, message_ts=ts).get(
        "permalink", ""
    )

    dm_message = "You have been RSVP'd to an event by <@{user}>"

    dm_blocks = block_formatters.format_event_dm(
        event=event,
        message=dm_message,
        event_link=permalink,
        rsvp_option=attend_type,
    )

    for other_attendee in added:
        try:
            misc.send_dm(
                slack_id=other_attendee,
                message=dm_message,
                slack_app=app,
                blocks=dm_blocks,
                metadata={
                    "event_type": "rsvp_by_other",
                    "event_payload": {
                        "ts": ts,
                        "channel": channel,
                        "rsvp_option": attend_type,
                        "event_time": int(event["start"].timestamp()),
                    },
                },
            )
        except SlackApiError as e:
            logger.error(f"Error sending DM: {e.response['error']}")
            logger.error(e.response)


@app.action("admin_event")
def admin_event(ack: slack_ack, body: dict) -> None:
    ack()

    # Get the original message this message was replied to
    ts = body["container"]["thread_ts"]
    channel = body["channel"]["id"]
    user = body["user"]["id"]

    event, _ = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

    # Check if the user is an event host
    if user in event.get("hosts", []) or user in admins:
        blocks = block_formatters.format_edit_event(event=event, ts=ts, channel=channel)
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
        # User is not an event host, send them a modal letting them know
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
def write_edit_event(ack: slack_ack, body: dict) -> None:
    """Handle the event edit modal submission"""
    ack()

    ts, channel = body["view"]["private_metadata"].split("-")

    # Events may be created in channels we're not a part of. We've been able to post the initial message but we can't retrieve it.
    app.client.conversations_join(channel=channel)

    # If the ts has a value of NEW, it means the user is creating a new event
    if ts == "NEW":
        # There's no existing event to retrieve
        event = {}
        event["rsvp_options"] = {}

    else:
        # Get a fresh copy of the event message
        event, message = misc.extract_event_data_from_pointer(
            slack_app=app, ts=ts, channel=channel
        )

    event, changes = misc.parse_event_changes(
        event=event, state_values=body["view"]["state"]["values"]
    )

    # Convert the event back into blocks
    blocks = block_formatters.format_event(event=event)

    # If the event already exists update the event, if it doesn't create the event post

    if ts == "NEW":
        # Check that we're in the channel and join if we're not
        current_channels = app.client.conversations_list(
            exclude_archived=True, types="public_channel,private_channel"
        )
        if channel not in [c["id"] for c in current_channels.get("channels", [])]:
            app.client.conversations_join(channel=channel)

        try:
            response = app.client.chat_postMessage(
                channel=channel,
                blocks=blocks,
                text=f"RSVP for {event['title']}!",
            )

            try:
                app.client.chat_postMessage(
                    channel=channel,
                    blocks=block_formatters.format_admin_prompt(event=event),
                    text="Admin tools",
                    thread_ts=response["ts"],
                )
            except SlackApiError as e:
                logger.error(f"Error posting message: {e.response['error']}")
                logger.error(e.response)
        except SlackApiError as e:
            logger.error(f"Error posting message: {e.response['error']}")
            logger.error(e.response)

    else:
        try:
            app.client.chat_update(
                channel=channel,
                ts=ts,
                blocks=blocks,
                text=message["text"],  # type: ignore
            )
        except SlackApiError as e:
            logger.error(f"Error updating message: {e.response['error']}")
            logger.error(e.response)

        # Check for meaningful changes
        if "description" in changes:
            changes.pop("description")

        if changes:
            # Let RSVP'd users know about the changes
            notify_users = [
                user
                for option in event["rsvp_options"].values()
                for user in option.keys()
            ]
            notify_users = list(set(notify_users))

            permalink = app.client.chat_getPermalink(
                channel=channel, message_ts=ts
            ).get("permalink", "")
            dm_blocks = block_formatters.format_event_dm(
                event=event,
                message="An event you RSVP'd to has been updated",
                event_link=permalink,
                rsvp_option="",
                highlight=changes,
            )
            for slack_id in notify_users:
                try:
                    misc.send_dm(
                        slack_id=slack_id,
                        message="The event you RSVP'd to has been updated",
                        slack_app=app,
                        blocks=dm_blocks,
                        metadata={
                            "event_type": "event_updated",
                            "event_payload": {
                                "ts": ts,
                                "channel": channel,
                                "rsvp_option": "",
                                "event_time": int(event["start"].timestamp()),
                            },
                        },
                    )
                except SlackApiError as e:
                    logger.error(f"Error sending DM: {e.response['error']}")
                    logger.error(e.response)


@app.action("edit_rsvp_modal")
def modal_edit_rsvp(ack: slack_ack, body: dict) -> None:
    """Push a view to edit the RSVPs for an event"""
    ack()

    # Get the original message this message was replied to
    ts, channel = body["view"]["private_metadata"].split("-")

    event, _ = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

    blocks = block_formatters.format_edit_rsvps(event=event, ts=ts, channel=channel)

    try:
        app.client.views_push(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "edit_rsvp_modal",
                "title": {"type": "plain_text", "text": "Edit RSVPs"},
                "blocks": blocks,
                "close": {"type": "plain_text", "text": "Cancel"},
                "private_metadata": f"{ts}-{channel}",
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)


@app.action("edit_rsvp_options_modal")
def edit_rsvp_options_modal(ack: slack_ack, body: dict) -> None:
    """Send the modal to edit the RSVP options"""
    ack()

    # Get the original message this message was replied to
    ts, channel = body["view"]["private_metadata"].split("-")

    event, _ = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

    blocks = block_formatters.format_edit_rsvp_options(
        event=event,
        ts=ts,
        channel=channel,
        member_emoji=config["slack"]["member_status_emoji"],
    )

    try:
        app.client.views_push(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "edit_rsvp_options_modal",
                "title": {"type": "plain_text", "text": "Edit RSVP Options"},
                "blocks": blocks,
                "close": {"type": "plain_text", "text": "Cancel"},
                "submit": {"type": "plain_text", "text": "Save"},
                "private_metadata": f"{ts}-{channel}",
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)


@app.view("edit_rsvp_options_modal")
def edit_rsvp_options(ack: slack_ack, body: dict) -> None:
    ack()

    ts, channel = body["view"]["private_metadata"].split("-")
    user = body["user"]["id"]

    event, message = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

    for option in body["view"]["state"]["values"]:
        old_name = option.replace("rsvp_option_", "")
        new_name = body["view"]["state"]["values"][option]["rsvp_option"]["value"]

        if old_name != new_name:
            event["rsvp_options"][new_name] = event["rsvp_options"][old_name]
            del event["rsvp_options"][old_name]

            # Post an audit message to the original message
            if old_name != "New Option":
                text = f"<@{user}> renamed the RSVP option `{old_name}` to `{new_name}`"
            else:
                text = f"<@{user}> added `{new_name}` as a new RSVP option"

            try:
                app.client.chat_postMessage(
                    channel=channel,
                    thread_ts=ts,
                    text=text,
                )
            except SlackApiError as e:
                logger.error(f"Error posting message: {e.response['error']}")
                logger.error(e.response)

            # Send DM to users as a record of the RSVP option change
            if old_name != "New Option":
                permalink = app.client.chat_getPermalink(
                    channel=channel, message_ts=ts
                ).get("permalink", "")

                dm_message = f"The RSVP option `{old_name}` has been renamed to `{new_name}` for an event you are attending"

                dm_blocks = block_formatters.format_event_dm(
                    event=event,
                    message=dm_message,
                    event_link=permalink,
                    rsvp_option=new_name,
                    highlight=["rsvp_option"],
                )

                for affected_user in event["rsvp_options"][new_name]:
                    try:
                        misc.send_dm(
                            slack_id=affected_user,
                            message=dm_message,
                            slack_app=app,
                            blocks=dm_blocks,
                            metadata={
                                "event_type": "rsvp_option_renamed",
                                "event_payload": {
                                    "ts": ts,
                                    "channel": channel,
                                    "rsvp_option": new_name,
                                    "event_time": int(event["start"].timestamp()),
                                },
                            },
                        )
                    except SlackApiError as e:
                        logger.error(f"Error sending DM: {e.response['error']}")
                        logger.error(e.response)

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

    # Since this is a view submission the modal has been closed
    # The previous modal in the stack doesn't include information
    # that has been edited here so it doesn't need updating


@app.action("delete_rsvp_option")
def delete_rsvp_option(ack: slack_ack, body: dict) -> None:
    ack()
    # pprint(body)

    ts, channel = body["view"]["private_metadata"].split("-")

    # Get event data
    event, message = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

    # Get the RSVP option to delete
    option = body["actions"][0]["value"].split("-")[1]

    # Delete the RSVP option from the event
    notify_users = event["rsvp_options"][option].copy()
    del event["rsvp_options"][option]

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

    # Update the current modal to show the RSVP option was deleted
    blocks = block_formatters.format_edit_rsvp_options(
        event=event,
        ts=ts,
        channel=channel,
        member_emoji=config["slack"]["member_status_emoji"],
    )

    try:
        app.client.views_update(
            view_id=body["view"]["id"],
            view={
                "type": "modal",
                "callback_id": "edit_rsvp_options_modal",
                "title": {"type": "plain_text", "text": "Edit RSVP Options"},
                "blocks": blocks,
                "close": {"type": "plain_text", "text": "Cancel"},
                "submit": {"type": "plain_text", "text": "Save"},
                "private_metadata": f"{ts}-{channel}",
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)

    # Post an audit message to the original message
    try:
        app.client.chat_postMessage(
            channel=channel,
            thread_ts=ts,
            text=f"<@{body['user']['id']}> deleted the RSVP option `{option}`\n\nThe following {'attendees were' if len(notify_users) > 1 else 'attendee was'} affected:\n{', '.join([f'<@{user}>' for user in notify_users])}",
        )
    except SlackApiError as e:
        logger.error(f"Error posting message: {e.response['error']}")
        logger.error(e.response)

    # Send DM to users as a record of the RSVP option change
    permalink = app.client.chat_getPermalink(channel=channel, message_ts=ts).get(
        "permalink", ""
    )
    dm_message = f"`{option}` has been deleted as an RSVP option for an event you were attending and has subsequently removed your RSVP"
    dm_blocks = block_formatters.format_event_dm(
        event=event,
        message=dm_message,
        event_link=permalink,
        rsvp_option=option,
    )
    for affected_user in notify_users:
        try:
            misc.send_dm(
                slack_id=affected_user,
                message=dm_message,
                slack_app=app,
                blocks=dm_blocks,
                metadata={
                    "event_type": "rsvp_option_deleted",
                    "event_payload": {
                        "ts": ts,
                        "channel": channel,
                        "rsvp_option": option,
                        "event_time": int(event["start"].timestamp()),
                    },
                },
            )
        except SlackApiError as e:
            logger.error(f"Error sending DM: {e.response['error']}")
            logger.error(e.response)


@app.action("add_rsvp_option")
def add_rsvp_option(ack: slack_ack, body: dict) -> None:
    """Add a new RSVP option to the event"""

    ack()

    ts, channel = body["view"]["private_metadata"].split("-")

    event, message = misc.extract_event_data_from_pointer(
        slack_app=app, ts=ts, channel=channel
    )

    event["rsvp_options"]["New Option"] = {}

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

    # Update the current modal to show the RSVP option was added
    blocks = block_formatters.format_edit_rsvp_options(
        event=event,
        ts=ts,
        channel=channel,
        member_emoji=config["slack"]["member_status_emoji"],
    )

    try:
        app.client.views_update(
            view_id=body["view"]["id"],
            view={
                "type": "modal",
                "callback_id": "edit_rsvp_options_modal",
                "title": {"type": "plain_text", "text": "Edit RSVP Options"},
                "blocks": blocks,
                "close": {"type": "plain_text", "text": "Cancel"},
                "submit": {"type": "plain_text", "text": "Save"},
                "private_metadata": f"{ts}-{channel}",
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)


# listen for app home opened events
@app.event("app_home_opened")
def update_home_tab(event: dict) -> None:
    """Update the home tab when the app is opened"""

    misc.update_home(user_id=event["user"], bot_id=bot_id, slack_app=app)


@app.action("create_event_modal")
def create_event_modal(ack: slack_ack, body: dict) -> None:
    """Send the modal to create a new event"""

    ack()

    # Open a new modal
    try:
        app.client.views_open(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "create_event",
                "title": {"type": "plain_text", "text": "Create Event"},
                "blocks": block_formatters.format_create_event_modal(
                    channel=config["slack"]["rsvp_channel"]
                ),
                "submit": {"type": "plain_text", "text": "Create"},
                "close": {"type": "plain_text", "text": "Cancel"},
                "clear_on_close": True,
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)


@app.view("create_event")
def create_event(ack: slack_ack, body: dict) -> None:
    """Handle the event creation modal submission"""
    ack()

    # Get the channel to post the event to
    channel = body["view"]["state"]["values"]["channel"]["channel"]["selected_channel"]

    # Get the user so we can set them as a host
    user = body["user"]["id"]

    # Create a placeholder event

    event = {
        "title": "New Event",
        "description": "New Event Description",
        "rsvp_options": {"Attending": {}},
        "start": datetime.now() + timedelta(days=3),
        "rsvp_deadline": datetime.now() + timedelta(days=2),
        "price": "Free",
        "hosts": [user],
    }

    # Generate an edit event modal with the fake event data
    blocks = block_formatters.format_edit_event(
        event=event,
        ts="NEW",
        channel=channel,
    )

    # Open a new modal
    try:
        app.client.views_open(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "write_edit_event",
                "title": {"type": "plain_text", "text": "Create Event"},
                "blocks": blocks,
                "close": {"type": "plain_text", "text": "Cancel"},
                "submit": {"type": "plain_text", "text": "Create"},
                "private_metadata": f"NEW-{channel}",
                "clear_on_close": True,
            },
        )
    except SlackApiError as e:
        logger.error(f"Error opening modal: {e.response['error']}")
        logger.error(e.response)
        pprint(blocks)


@app.action("event_detail_link")
def ignore_link_press(ack: slack_ack) -> None:
    """Ignore the link press event"""
    ack()


# Retrieve all users in the admin group at runtime
admins = []
if config["slack"].get("admin_group"):
    try:
        admin_group = app.client.usergroups_users_list(
            usergroup=config["slack"]["admin_group"]
        )
        admins = admin_group["users"]
    except SlackApiError as e:
        logger.error(f"Error retrieving admin group: {e.response['error']}")
        logger.error(e.response)

if admins:
    logger.info(f"{len(admins)} admins set")
else:
    logger.warning(
        "Something went wrong with the admin group (or it wasn't specified). Only event hosts will be able to edit events"
    )

bot_id: str = app.client.auth_test().get("user_id", "")

users = []
run = True
# The home mode renders the app home for every user in the workspace
if "--home" in sys.argv:
    run = False
    # Update homes for all slack users
    logger.info("Updating homes for all users")

    users = misc.get_users(slack_app=app)
    logger.info(f"Found {len(users)} users")

    x = 1

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        for user in users:
            futures.append(
                executor.submit(
                    misc.update_home,
                    user_id=user,
                    bot_id=bot_id,
                    slack_app=app,
                    silent=True,
                )
            )
        for future in as_completed(futures):
            try:
                future.result()
                x += 1
                logger.info(f"Updated home ({x}/{len(users)})")
            except Exception as e:
                logger.error(f"Error updating home: {e}")

    logger.info(f"All homes updated ({x - 1})")

# The clean mode archives all events that finished more than a day ago
if "--clean" in sys.argv:
    run = False
    logger.info("Cleaning up old events")

    if not users:
        users = misc.get_users(slack_app=app)[:20]
        logger.info(f"Found {len(users)} users")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    collated_events = {}

    x = 1

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        for user in users:
            futures.append(
                executor.submit(
                    misc.get_events_from_user,
                    user_id=user,
                    bot_id=bot_id,
                    slack_app=app,
                )
            )
        for future in as_completed(futures):
            try:
                events = future.result()

                for event in events:
                    if event["ts"] not in collated_events:
                        collated_events[event["ts"]] = event
                    else:
                        if (
                            event["event_time"]
                            > collated_events[event["ts"]]["event_time"]
                        ):
                            collated_events[event["ts"]] = event
                x += 1
                logger.info(f"Got collated events from ({x}/{len(users)})")
                logger.info(f"Total events found: {len(collated_events)}")
            except Exception as e:
                logger.error(f"Error getting events: {e}")

    # Remove events that are older than our cutoff
    cutoff_days = int(config.get("cleanup_days", 5))
    cutoff = datetime.now() - timedelta(days=cutoff_days)
    cutoff = cutoff.timestamp()
    collated_events = {
        k: v for k, v in collated_events.items() if v["event_time"] < cutoff
    }
    logger.info(
        f"Total events after cutoff of {cutoff_days} days: {len(collated_events)}"
    )

    # Open existing archive
    try:
        with open("archived_events.json", "r") as f:
            archived_events: dict = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        archived_events = {}

    for event in collated_events.values():
        event, message = misc.extract_event_data_from_pointer(
            slack_app=app, ts=event["ts"], channel=event["channel"]
        )
        archived_events[message["ts"]] = event

    # Save the archived events back to the file
    with open("archived_events.json", "w") as f:
        json.dump(archived_events, f, indent=4, default=str)
        logger.info("Archived events saved")

    # Delete the event posts
    for event in collated_events.values():
        event_time_str = datetime.fromtimestamp(event["event_time"]).strftime(
            "%Y-%m-%d %H:%M"
        )
        logging.info(f"Deleting event {event['ts']} ({event_time_str})")
        misc.delete_event(slack_app=app, ts=event["ts"], channel=event["channel"])


if run:
    # Start the app
    if __name__ == "__main__":
        handler = SocketModeHandler(app, config["slack"]["app_token"])
        handler.start()
