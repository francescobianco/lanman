"""ntfy notifications for lanman (send only, no remote control).

The channel is configured per installation, either with the LANMAN_NTFY
environment variable or with a one-line file <data dir>/ntfy containing a
topic name ("piave29") or a full URL ("https://ntfy.example.com/topic").
Without configuration nothing is sent.
"""
import os
import threading
import urllib.parse
import urllib.request

DEFAULT_SERVER = "https://ntfy.sh/"


def target(data_dir):
    value = os.environ.get("LANMAN_NTFY")
    if not value:
        try:
            with open(os.path.join(data_dir, "ntfy")) as f:
                value = f.read().strip()
        except OSError:
            return None
    if not value:
        return None
    return value if "://" in value else DEFAULT_SERVER + value.strip("/")


def send(url, title, message):
    """Fire and forget POST to ntfy; the title goes in the query string so it
    can carry any UTF-8 text."""
    if not url:
        return
    query = urllib.parse.urlencode({"title": title})

    def post():
        try:
            req = urllib.request.Request(url + "?" + query, data=message.encode("utf-8"),
                                         headers={"User-Agent": "lanman"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            print("ntfy: %r" % e, flush=True)

    threading.Thread(target=post, daemon=True).start()
