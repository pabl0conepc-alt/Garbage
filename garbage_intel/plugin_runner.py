"""Child side of a plugin run. Executed as ``python -I -c <this source>``.

Protocol on the inherited stdin/stdout, one JSON object per line:

* host -> child: the job ``{"plugin_dir", "entry", "input", "timeout"}``;
* child -> host: ``{"op": "fetch", "id", "url", "headers"}`` and then waits
  for ``{"id", "status", "headers", "body_base64", "final_url"}`` or
  ``{"id", "error"}``;
* child -> host: ``{"op": "result", "findings": [...]}`` or
  ``{"op": "error", "message"}`` as the last line.

The plugin's own ``print`` goes to stderr so it cannot forge protocol lines.
Direct sockets are replaced before the plugin is imported, so the only way
out is ``ctx.fetch``, which the host checks against the declared hosts. This
is defence in depth, not a sandbox: a plugin is code the analyst chose to
trust. On POSIX the address space and CPU time are capped.

This file must not import ``garbage_intel``: ``-I`` keeps the package off
the child's path.
"""

import base64
import importlib.util
import json
import os
import socket
import sys

PROTOCOL_OUT = None
PROTOCOL_IN = sys.stdin


def send(message):
    PROTOCOL_OUT.write(json.dumps(message) + "\n")
    PROTOCOL_OUT.flush()


class Response:
    def __init__(self, reply):
        self.status = reply.get("status", 0)
        self.headers = reply.get("headers") or {}
        self.url = reply.get("final_url", "")
        self.body = base64.b64decode(reply.get("body_base64") or "")

    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class Context:
    def __init__(self, job):
        self.type = job["input"]["type"]
        self.value = job["input"]["value"]
        self._next = 0

    def fetch(self, url, headers=None):
        """GET through the host, limited to the plugin's declared hosts."""
        self._next += 1
        send({"op": "fetch", "id": self._next, "url": str(url), "headers": dict(headers or {})})
        reply = json.loads(PROTOCOL_IN.readline() or "{}")
        if reply.get("id") != self._next:
            raise RuntimeError("protocol error: unexpected reply")
        if reply.get("error"):
            raise RuntimeError(reply["error"])
        return Response(reply)


def _refuse(*args, **kwargs):
    raise PermissionError("plugins reach the network only through ctx.fetch")


def _limit(timeout):
    try:
        import resource
    except ImportError:
        return
    for name, value in (("RLIMIT_AS", 768 * 1024 * 1024), ("RLIMIT_CPU", int(timeout) + 2)):
        limit = getattr(resource, name, None)
        if limit is not None:
            try:
                resource.setrlimit(limit, (value, value))
            except (ValueError, OSError):
                pass


def main():
    global PROTOCOL_OUT
    PROTOCOL_OUT = os.fdopen(os.dup(1), "w", encoding="utf-8", buffering=1)
    # Even os.write(1, ...) from the plugin lands on stderr from here on.
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    job = json.loads(PROTOCOL_IN.readline())
    _limit(job.get("timeout", 20))
    socket.socket = _refuse
    socket.create_connection = _refuse
    socket.getaddrinfo = _refuse
    socket.socketpair = _refuse
    plugin_dir = job["plugin_dir"]
    sys.path.insert(0, plugin_dir)
    os.chdir(plugin_dir)
    try:
        spec = importlib.util.spec_from_file_location("garbage_plugin", os.path.join(plugin_dir, job["entry"]))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        findings = module.run(Context(job))
        send({"op": "result", "findings": findings if isinstance(findings, list) else []})
    except Exception as error:  # noqa: BLE001 - reported to the host, never raised
        send({"op": "error", "message": f"{type(error).__name__}: {error}"[:500]})


if __name__ == "__main__":
    main()
