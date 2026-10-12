"""One safe CMD delayed-expansion shape; percent expansion stays unresolved.

CMD expands percent variables before executing a compound line. Never infer them
from SET earlier on that line. Delayed expansion is supported only with explicit
/v:on, literal SET followed by ECHO, no control flow or metacharacter values.
"""
import re

def reconstruct(text):
    match=re.fullmatch(r'(?is)\s*cmd(?:\.exe)?\s+/v:on\s+/c\s+"set ([a-z_][a-z0-9_]*)=([a-z0-9 ._-]{1,128})&&\s*echo (!\1!)"\s*',text)
    if not match:return None
    start,end=match.span(3)
    return text[:start]+match.group(2)+text[end:],{'start':start,'end':end,'variable':match.group(1),'mode':'explicit_delayed_expansion'}
