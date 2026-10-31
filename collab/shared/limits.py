"""Protocol sizes, resource limits and timing defaults."""

MAX_FRAME = 2_000_000
UDP_MTU = 1100
CHUNK = 320
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_CHUNKS = (MAX_FILE_SIZE + CHUNK - 1) // CHUNK
MAX_USERNAME = 24
MAX_PACKET_ID = 80
MAX_FILENAME = 255
MAX_CHAT_CHARS = 1000
MAX_ERROR_CHARS = 120
SEND_WINDOW = 6
CLIENT_RETRIES = 15
SERVER_RETRIES = 12
RETRY_TIMEOUT = 0.25
CONNECT_TIMEOUT = 5
CLIENT_LOGIN_TIMEOUT = 5
LOGOUT_TIMEOUT = 0.5
SHUTDOWN_TIMEOUT = 3
CONTROL_TIMEOUT = 0.5
UDP_PATH_CHALLENGE_TIMEOUT = 2
UDP_PATH_CHALLENGE_INTERVAL = 0.5
HTTP_REQUEST_TIMEOUT = 2
FILE_PROGRESS_INTERVAL = 0.1
LOGIN_TIMEOUT = 4
SESSION_TIMEOUT = 2
HEARTBEAT_INTERVAL = 2
SESSION_EXPIRY = 10
SESSION_CHECK_INTERVAL = 0.5
UDP_TIMEOUT = 0.2
SERVER_POLL_TIMEOUT = 0.3
RETRY_POLL_INTERVAL = 0.04
SEND_POLL_INTERVAL = 0.012
MAX_SEEN_PACKETS = 200_000
CHAT_SERVER_TIMEOUT = 5
CHAT_CONFIRM_TIMEOUT = 10
CHAT_CACHE_TTL = 60
CHAT_CACHE_LIMIT = 4096
CHAT_OUTGOING_LIMIT = 32
CHAT_GAP_TIMEOUT = 1
CHAT_STREAM_WINDOW = 64
CHAT_STREAM_LIMIT = 128
CHAT_FAILURE_REASONS = frozenset(
    {
        "recipient_offline",
        "self_recipient",
        "no_recipients",
        "recipient_disconnected",
        "delivery_timeout",
    }
)
TCP_TYPES = frozenset(
    {
        "hello",
        "challenge",
        "login",
        "welcome",
        "error",
        "logout",
        "users",
        "chat_status",
        "file_status",
        "file_receipt",
        "file_abort",
        "file_cancel",
    }
)
CLIENT_UDP_TYPES = frozenset({"heartbeat", "ack", "data", "path_response"})
SERVER_UDP_TYPES = frozenset({"presence", "ack", "data", "path_challenge"})
DATA_KINDS = frozenset({"chat", "file_start", "file_chunk", "file_end"})

FILE_IDLE_TIMEOUT = 30
FILE_TRANSFER_TIMEOUT = 15 * 60
FILE_RESULT_TTL = 60
FILE_CACHE_LIMIT = 4096
FILE_ACTIVE_LIMIT = 256
FILE_OUTGOING_LIMIT = 2
FILE_WRITE_QUEUE = 256
FILE_MAILBOX_LIMIT = 32
FILE_FAILURE_REASONS = frozenset(
    {
        "recipient_offline",
        "self_recipient",
        "no_recipients",
        "recipient_disconnected",
        "delivery_timeout",
        "metadata_conflict",
        "chunk_conflict",
        "hash_mismatch",
        "disk_error",
        "capacity_exceeded",
        "source_disconnected",
        "source_aborted",
    }
)
FILE_HASH_BUDGET = (
    64 * 1024 * 1024
)
FILE_HASH_ENTRY_BYTES = 256
