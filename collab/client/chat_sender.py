"""Outgoing chat admission, confirmation waiting and send events."""

import json
import threading
import time
from collab.shared.limits import CHAT_OUTGOING_LIMIT, CHAT_CONFIRM_TIMEOUT
from collab.shared.protocol import validate_udp
from collab.transport.udp import validate_udp_size


class ChatSender:
    """Manage outgoing chat admission, progress events, and final result waiting."""

    def __init__(self, client):
        self.client = client

    def _chat_accepted(self, mid, record):
        client = self.client
        if not record["accepted"] and (
            record["result"] is None or record["result"]["state"] != "rejected"
        ):
            record["accepted"] = True
            client.events.put({"type": "chat_accepted", "id": mid, "to": record["to"]})

    def _receive_chat_status(self, msg, session):
        client = self.client
        record = client.outgoing_chats.get(msg["id"])
        if (
            record is None
            or record["session"] is not session
            or record["result"] is not None
        ):
            return
        record["result"] = msg
        if msg["state"] != "rejected":
            self._chat_accepted(msg["id"], record)
        # A final TCP result supersedes a lost ingress ACK, including rejection.
        with client.pending_lock:
            event = client.pending.get(msg["id"])
            if event is not None:
                event.set()
        record["done"].set()

    def _preflight_chat(self, packet):
        client = self.client
        raw = dict(packet, **{"from": client.name, "token": client.token})
        validate_udp(raw, from_client=True)
        validate_udp_size(raw)
        names = (
            [n for n in client.names if n != client.name]
            if packet["to"] == "*"
            else [packet["to"]]
        )
        # Check forwarded metadata before reserving an outgoing chat slot.
        destination = max(names or [client.name], key=lambda n: len(json.dumps(n)))
        forwarded = dict(
            packet,
            **{
                "from": client.name,
                "to": destination,
                "meta": {
                    "sender_session": "0" * 32,
                    "channel": packet["to"],
                    "sequence": 2**63 - 1,
                },
            },
        )
        validate_udp_size(forwarded)

    def chat(self, recipient, text):
        """Send chat and wait for the server's final recipient result.

        Args:
            recipient: Account username, or * for broadcast.
            text: Chat content satisfying character and encrypted-datagram limits.

        Raises:
            ValueError: Packet validation or datagram-size checks fail.
            ConnectionError: The session ends or changes while sending.
            TimeoutError: Delivery remains unconfirmed before the confirmation deadline.
            RuntimeError: Admission capacity is exhausted or final delivery fails.
        """
        client = self.client
        session = client._capture_session()
        packet = client.packet(recipient, "chat", text)
        with client._state_lock:
            if client._session is not session:
                raise ConnectionError("Session ended before sending chat")
            self._preflight_chat(packet)
            if len(client.outgoing_chats) >= CHAT_OUTGOING_LIMIT:
                raise RuntimeError("Too many chats awaiting confirmation")
            record = {
                "session": session,
                "to": recipient,
                "done": threading.Event(),
                "result": None,
                "accepted": False,
                "reported": False,
            }
            client.outgoing_chats[packet["id"]] = record
            deadline = time.monotonic() + CHAT_CONFIRM_TIMEOUT
            client.events.put(
                {"type": "chat_sending", "id": packet["id"], "to": recipient}
            )
        try:
            try:
                client.send_packets([packet], session=session)
                with client._state_lock:
                    if client._session is not session:
                        raise ConnectionError("Session ended while sending chat")
                    if (
                        record["result"] is None
                        or record["result"]["state"] != "rejected"
                    ):
                        self._chat_accepted(packet["id"], record)
            except TimeoutError:
                # Ingress may have succeeded while its ACK was lost; wait for final TCP status.
                pass
            while not record["done"].is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Chat delivery is unconfirmed")
                record["done"].wait(min(0.1, remaining))
            with client._state_lock:
                if client._session is not session:
                    raise ConnectionError("Session ended while sending chat")
                result = record["result"]
                if result is None:
                    raise ConnectionError("Session ended while sending chat")
                if result["state"] != "delivered":
                    reasons = ", ".join(
                        f"{item['name']}: {item['reason']}"
                        for item in result["failures"]
                    )
                    raise RuntimeError("Chat delivery failed: " + reasons)
                record["reported"] = True
                client.events.put(dict(result, type="chat_delivered"))
                client.events.put(
                    {"type": "sent", "id": packet["id"], "to": recipient, "text": text}
                )
        except (OSError, RuntimeError, ValueError) as exc:
            with client._state_lock:
                if not record["reported"]:
                    record["reported"] = True
                    client.events.put(
                        {
                            "type": "chat_send_failed",
                            "id": packet["id"],
                            "to": recipient,
                            "reason": str(exc),
                            "result": record["result"],
                        }
                    )
                    client.events.put({"type": "error", "message": str(exc)})
            raise
        finally:
            with client._state_lock:
                if client.outgoing_chats.get(packet["id"]) is record:
                    del client.outgoing_chats[packet["id"]]
