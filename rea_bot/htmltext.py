"""Normalized visible text from HTML. Scripts and styles are dropped; nothing is executed."""
import re
from html.parser import HTMLParser


class _Visible(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data:
            self.parts.append(data)


def html_text(value):
    """Collapse visible text. JavaScript is not run, so client-rendered text is absent."""
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    if not isinstance(value, str):
        raise ValueError('HTML text expects a string or bytes.')
    parser = _Visible()
    parser.feed(value)
    parser.close()
    return re.sub(r'\s+', ' ', ' '.join(parser.parts)).strip()
