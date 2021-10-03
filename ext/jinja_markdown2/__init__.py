import textwrap

import markdown
from jinja2.nodes import CallBlock
from jinja2.ext import Extension

__all__ = ["EXTENSIONS", "MarkdownExtension", "EXTENSION_CONFIG"]

EXTENSIONS = [
    "admonition",
    "attr_list",
    "codehilite",
    "smarty",
    "tables",
    "pymdownx.betterem",
    "pymdownx.caret",
    "pymdownx.details",
    "pymdownx.emoji",
    "pymdownx.keys",
    "pymdownx.magiclink",
    "pymdownx.mark",
    "pymdownx.smartsymbols",
    "pymdownx.superfences",
    "pymdownx.tabbed",
    "pymdownx.tasklist",
    "pymdownx.tilde",
]
EXTENSION_CONFIG = {}


class MarkdownExtension(Extension):
    tags = set(['markdown'])

    def __init__(self, environment):
        super(MarkdownExtension, self).__init__(environment)
        environment.extend(
            markdowner=markdown.Markdown(extensions=EXTENSIONS, extension_configs=EXTENSION_CONFIG)
        )

    def parse(self, parser):
        lineno = next(parser.stream).lineno
        body = parser.parse_statements(
            ['name:endmarkdown'],
            drop_needle=True
        )
        return CallBlock(
            self.call_method('_render_markdown'),
            [],
            [],
            body
        ).set_lineno(lineno)

    def _render_markdown(self, caller):
        text = caller()
        text = self._dedent(text)
        return self.environment.markdowner.convert(text)

    def _dedent(self, text):
        return textwrap.dedent(text.strip("\n"))
