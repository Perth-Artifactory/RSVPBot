divider = [{"type": "divider"}]
text = [{"type": "section", "text": {"type": "mrkdwn", "text": ""}}]
context = [
    {
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": ""}],
    }
]
quote = [
    {
        "type": "rich_text",
        "elements": [
            {
                "type": "rich_text_quote",
                "elements": [
                    {
                        "type": "text",
                        "text": "",
                    }
                ],
            }
        ],
    }
]
field = {"type": "mrkdwn", "text": ""}
header = [{"type": "header", "text": {"type": "plain_text", "text": "", "emoji": True}}]

accessory_image = {"type": "image", "image_url": "", "alt_text": ""}

button = {"type": "button", "text": {"type": "plain_text", "text": ""}}

actions = [{"type": "actions", "block_id": "button_actions", "elements": []}]

text_question = {
    "type": "input",
    "element": {
        "type": "plain_text_input",
        "action_id": "",
        "placeholder": {"type": "plain_text", "text": "", "emoji": True},
    },
    "label": {"type": "plain_text", "text": "", "emoji": True},
}

option = {
    "text": {"type": "plain_text", "text": "", "emoji": True},
    "value": "",
}

radio_buttons = {
    "type": "input",
    "element": {
        "type": "radio_buttons",
        "options": [],
        "action_id": "",
    },
    "label": {"type": "plain_text", "text": "", "emoji": True},
}

static_dropdown = {
    "type": "input",
    "element": {
        "type": "static_select",
        "placeholder": {"type": "plain_text", "text": "", "emoji": True},
        "options": [],
        "action_id": "",
    },
    "label": {"type": "plain_text", "text": "", "emoji": True},
}

external_static_dropdown = {
    "action_id": "",
    "type": "external_select",
    "placeholder": {"type": "plain_text", "text": "Select an item"},
    "min_query_length": 4,
}

multi_static_dropdown = {
    "type": "input",
    "element": {
        "type": "multi_static_select",
        "placeholder": {"type": "plain_text", "text": "", "emoji": True},
        "options": [],
        "action_id": "",
    },
    "label": {"type": "plain_text", "text": "", "emoji": True},
}

multi_users_select = {
    "type": "input",
    "element": {
        "type": "multi_users_select",
        "placeholder": {"type": "plain_text", "text": "", "emoji": True},
        "action_id": "",
    },
    "label": {"type": "plain_text", "text": "", "emoji": True},
}

date_select = {
    "type": "input",
    "element": {
        "type": "datepicker",
        "placeholder": {
            "type": "plain_text",
            "text": "",
            "emoji": True,
        },
        "action_id": "",
    },
    "label": {"type": "plain_text", "text": "", "emoji": True},
}

cal_select = {
    "type": "datepicker",
    "placeholder": {"type": "plain_text", "text": ""},
}

file_input = {
    "type": "input",
    "label": {"type": "plain_text", "text": ""},
    "element": {
        "type": "file_input",
    },
}

checkboxes = {
    "type": "input",
    "element": {"type": "checkboxes", "options": []},
    "label": {
        "type": "plain_text",
        "text": "",
    },
}

image = {
    "type": "image",
    "image_url": "",
    "alt_text": "An image from Taiga",
}

base_input = {
    "type": "input",
    "element": {},
    "label": {"type": "plain_text", "text": "", "emoji": True},
}

rich_text_section = (
    {
        "type": "rich_text_section",
        "elements": [],
    },
)
rich_text_element = {"type": "text", "text": ""}
