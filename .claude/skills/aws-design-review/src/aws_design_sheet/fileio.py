"""Writing workspace files so that no reader, and no second writer, ever meets half a file.

Several agents may work in one workspace at once. A file written in place can be read while it is half written, and
two writers that each read, change and write one file lose each other's work. Files more than one process may write
are therefore one file per record (a look per image, a ledger per document), and every write goes to a temporary
file beside the target that is renamed over it in one step.
"""
import os
import time
import uuid
from pathlib import Path


def write_atomic(path, data):
    """Write bytes to a path by renaming a finished temporary file over it."""
    path = Path(path);path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp')
    temporary.write_bytes(data)
    for attempt in range(40):
        try:
            os.replace(temporary, path);return path
        except PermissionError:
            # Windows refuses the rename while another process holds the target open for a moment.
            if attempt == 39:
                temporary.unlink(missing_ok=True);raise
            time.sleep(0.05)
    return path
