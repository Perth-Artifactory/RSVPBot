# RSVPBot

Manage RSVPs for events from Slack

## Setup

* Specify event templates via `events.json`
* Set up `config.json`

### Event template fields

> [!NOTE]  
> Nested events are RSVPable events that occur *within* another event and do not need to share the parent event title or start time.

* `calendar_name`: *(required)* The name of the event on Google Calendar. This will be used to automatically post RSVPs for new events.
* `title`: *(optional | default: `calendar_name`)* The name of the event as you want it to appear in Slack. Will default to `calendar_name` if not specified. This is used for nested events.
* `description`: *(optional | default: `Come on down!`)* The description of the event as you want it to appear in the RSVP post. The description used in the Google Calendar entry is not used.
* `price`: *(optional)* The price of the event. This is a freeform text field and can include a sentence if required.
* `rsvp_deadline`: *(optional | default: `0`)* How many hours before the event RSVPs close. If set to `0` The "RSVP By:" field will be omitted from event posts.
* `event_offset`: *(optional | default: `0`)* Specify how many hours should be added to the event start time specified in the Google Calendar entry. (can be negative) This is used for nested events.
* `rsvp_options`: *(optional | default: `Attending`)* An array of RSVP options
* `hosts`: *(optional | default: `[]`)* An array of Slack IDs that will be listed as event hosts.
* `regulars`: *(optional | default: `[]`)* An array of Slack IDs that will be pinged when an event is created.
* `auto_rsvp`: *(optional | default: `[]`)* An array of Slack IDs that will be auto RSVP'd when an event is created. Auto RSVPs will use the **first** option listed by `rsvp_options`.
* `days_before`: *(optional | default: `config.json`/`days_before`)* How many days before the event start does the RSVP post get posted. The exact time of the post will be controlled by the cron entry for `cron.py`
* `channel_override`: *(optional | default: `config.json`/`slack`/`rsvp_channel`)* Channel to post the RSVP in.
* `image`: *(optional | default: `None`)* The URL to an image to attach to the RSVP post

## Running

* Run `app.py` however you want
* Run `cron.py` on a daily schedule to post new events, `--debug` to enable debug logging 

### Manual event creation

Events can be manually created via `cron.py`

* `--manual=[eventid]` Use the key from an event specified in `events.json` as the `eventid`
* `--start=[epoch_time]` Specify a start time for the event. If no start time is specified the event will be assumed to be now + 2 days + the days_before offset specified in `events.json`/default: `4`
