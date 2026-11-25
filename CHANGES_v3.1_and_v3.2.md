# SecureSMS v3.1 — "Chats" tab + why emulator → phone does not arrive

## 1. New: Chats tab (conversation list)
Tabs are now **Chats | Chat | RSA vs ECC | My keys** (same XML/dark style as before).

* Every contact with at least one message is a row: address, preview, key-state line (e.g. `ECC P-256 · verify fingerprint`), time, unread badge. Newest first. The tab title shows the unread total, e.g. `Chats (2)`.
* **When someone writes to you first**, their conversation appears in your list by itself as a received message:
  `🔒 <number> wants to start a secure ECC P-256 conversation. Verify their fingerprint to continue.`
  (It is a local note created when a valid, signed KEY_REQUEST arrives. It is *not* a request you must accept; trust is still decided in the fingerprint step.) The row shows `!` until you verify, then `🔒`.
* Tap a row → opens the Chat tab with that number and the mode of its latest message. Long-press → delete the conversation's messages (keys stay). **+ New conversation** → Chat tab with an empty number.
* Rows also show your own sent messages with status marks: `⏳` waiting for key exchange/verification, `↑` sending, `✓` sent, `✓✓` delivered, `⚠ not sent`.
* A changed identity key also adds a warning note to the conversation.

Files: `messaging/Messenger.kt` (+`conversations()`, `unread()`, `lastIncomingId()`, `ConversationRow`, `SYSTEM_INFO`, request note in `handleKq`), `ui/MainActivity.kt`, new `layout/tab_conversations.xml`, `layout/item_conversation.xml`, `drawable/bg_avatar.xml`, `drawable/bg_badge.xml`, `layout/activity_main.xml`, `values/strings.xml`. Saved data format is unchanged (no serialized class was modified), so your existing state still loads.

Tests: 52 pass on a JVM (47 of yours + 5 new in `ConversationListTest.kt`: request shows in the list, unread, sender view, no repeated notes, ordering/delete, key-change note). `MessengerTest.Phone.incoming()` now ignores the local note. The UI/XML part is **not compiled** (no Android SDK where this was produced).

## 2. Why a message sent from the emulator never reaches the physical phone
1. **The emulator's SMS is simulated.** It can only talk to other emulators (by console port: `5554`, `5556`). It never reaches a carrier, so a real phone can never receive it, and a real phone can never SMS an emulator. `sendTextMessage()` to a real number "succeeds" silently, so the app shows *sent* while nothing leaves the PC.
2. **Your HybridTransport.** If you type a *number*, it uses SMS (case 1). Only if the SMS call *throws* does it fall back to `127.0.0.1` — that is the emulator talking to **itself**, which creates a conversation with "127.0.0.1" (you will now see it in Chats). If you type the phone's *IP*, the first frame can reach the phone over Wi-Fi, but the phone answers to the IP it saw as the sender. The emulator sits behind NAT, so the phone sees the **PC's** address and its reply goes to the PC, where nothing listens on port 7777. Even with port forwarding, the emulator would see the reply coming from `10.0.2.2`, and `Messenger` ignores a KEY_RESPONSE whose sender address does not match the contact it wrote to. Result: the handshake can never finish.

### What works (pick one for the demo)
| Setup | How |
|---|---|
| **Two emulators** (SMS code path) | Start two AVDs. In emulator A use the contact number `5556`; in B use `5554`. Real SMS API, multipart, SmsReceiver. |
| **Two physical phones, SMS** | Two SIMs, normal numbers. |
| **Two physical phones, Wi-Fi (IP)** | Same Wi-Fi without "client isolation". Type the other phone's IP (shown in **My keys**). No NAT, so addresses match. |
| **Emulator + phone** | Not reliable with the current address-as-identity design. Use one of the rows above, or change the transport to carry an explicit sender id inside the TCP line (optional next step; not done here because it cannot be verified without devices). |

Quick check that delivery works at all: on the receiving phone open **Chats**. If the sender's number/IP appears with "wants to start a secure … conversation", the first frame arrived.

---
# v3.2 fixes

## Chats tab was invisible (my bug in v3.1)
`tab_chat.xml` has an outer, always-visible, opaque FrameLayout. In `activity_main.xml` the new Chats layout was included *before* it, so the Chat tab's background was drawn on top of the list: the data was there (the tab title counted the conversation) but covered. Fix: `tab_conversations` is now included **after** `tab_chat`. Rule for the future: every tab layout that is toggled with visibility must be included after `tab_chat`.

## "Unexpected response: ignored an unexpected ECC P-256 key response"
Means: this phone received a KEY_RESPONSE it was not waiting for. v3.2 changes:
* A **duplicate** of a response already processed is ignored silently (some phones/carriers deliver the same SMS twice).
* A real unexpected response now says **why**: no exchange in progress / this phone did not start it / it belongs to an older request that was replaced by Restart or a second request.
Tests: `KeyResponseHandlingTest` (54 JVM tests pass in total).

## Reminder: nothing is sent until BOTH sides verified
Phone A sends → phone B auto-answers → **A must tap Verify → Trust** (only then A sends its confirmation and the queued message) → **B must also Verify → Trust** to read it. If A never verifies, B never receives the message. This is by design.
