#!/usr/bin/env python3
"""Check local links, anchors, and assets in the Eleventy output."""
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlsplit, unquote
OUT = Path(__file__).resolve().parent / "dist"

class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.ids = [], set()
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            if attrs['id'] in self.ids: raise ValueError('Duplicate ID: ' + attrs['id'])
            self.ids.add(attrs['id'])
        for key in ('href', 'src'):
            if key in attrs: self.links.append(attrs[key])

def check():
    parsed = {}
    for path in OUT.glob('*.html'):
        parser = Links(); parser.feed(path.read_text()); parsed[path] = parser
    for path, parser in parsed.items():
        for link in parser.links:
            url = urlsplit(link)
            if url.scheme or url.netloc: continue
            target = ((OUT / unquote(url.path).lstrip('/')) if url.path.startswith('/') else (path.parent / unquote(url.path))).resolve() if url.path else path
            if not target.is_relative_to(OUT.resolve()): raise ValueError(f'Link escapes public output: {link}')
            if not target.exists(): raise ValueError(f'{path.name}: missing {link}')
            if url.fragment and target in parsed and unquote(url.fragment) not in parsed[target].ids:
                raise ValueError(f'{path.name}: missing anchor {link}')
    print(f'Checked {len(parsed)} pages: local links, assets, anchors, and duplicate IDs.')

if __name__ == "__main__":
    if not (OUT / "index.html").is_file(): raise SystemExit("Build the site first: npm run build")
    check()
