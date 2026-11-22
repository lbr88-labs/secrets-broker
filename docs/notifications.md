# Notifications

All notification providers are optional and can be configured in the UI
(Settings) or via environment variables. When an agent requests a secret, the
broker sends the same approval message to every configured channel.

## ntfy

Set `NTFY_URL` to a topic on a server you control, for example
`https://ntfy.example.com/secrets-broker`, and set `NTFY_TOKEN` to that topic's
access token. The broker sends `Authorization: Bearer <token>`. ACL the topic
so only your user can read it and only this token can write it. The one-time
approval tokens are stored in the ntfy `Actions` header, so a reader of the
topic can approve until they expire (about 10 minutes).

If the broker is behind Cloudflare Access, bypass Access for `POST /approve/*`
only. The ntfy app runs that POST itself and does not send an Access cookie.
Keep `GET /approve/*` and the rest of the hostname behind Access.

The message body names the bot, the secret, the duration and the command, then
a separate line for the bot-supplied reason (capped at 120 characters). It does
not contain an `/approve/` URL. Allow once, 1h, 24h and deny are ntfy `http`
action buttons: each is a `POST` carrying a one-time bearer token that the
broker deletes when it is used.

## Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather).
2. Set `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` and `TELEGRAM_USER_ID` (or save
   all three in Settings). Approvals are ignored until both the chat id and the
   user id are set.
3. The broker never learns those ids from an incoming message. `/start` from
   another chat does not move the approval channel.

Approval messages contain inline buttons (once / 1h / 24h / 7d / permanent /
deny). A callback is accepted only when `from.id` equals the configured user
and `message.chat.id` equals the configured chat. The broker handles callbacks
with long polling, so no public webhook is required.

## Gotify

Set `GOTIFY_URL` (for example `http://gotify:80`) and `GOTIFY_TOKEN` (an
application token created in Gotify). Messages are sent to `/message` with the
`X-Gotify-Key` header.

## wxpush (WeChat)

[wxpush](https://github.com/frankiejun/wxpush) sends WeChat notifications.

Set `WXPUSH_URL` (e.g. `https://wxpush.example.com`) and `WXPUSH_TOKEN`. The
broker posts form fields `title`, `content` and `token` to `/wxsend` with the
token in the `Authorization` header.

## Confirm step

`GET /approve/<request-id>?d=once&exp=<timestamp>&sig=<hmac>` shows a confirm
form and does not decide. The form posts the same HMAC fields. `d` can be
`once`, `1h`, `24h`, `7d`, `always` or `deny`. The signature expires after 10
minutes and a request can only be decided once.

ntfy buttons do not use that URL. They `POST` to `/approve/<id>` with
`Authorization: Bearer <one-time token>`. Gotify and wxpush receive the same
text as ntfy and no capability URL; approve those requests from the admin page
or from Telegram.
