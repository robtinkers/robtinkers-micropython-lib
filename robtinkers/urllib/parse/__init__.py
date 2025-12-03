def charsub(s, subs, safe=''):
    """Replace multiple characters in a string in one pass."""
    result = []
    i = 0
    for j, c in enumerate(s):
        if c in subs and c not in safe:
            result.append(s[i:j])
            result.append(subs[c])
            i = j + 1
    result.append(s[i:])
    return ''.join(result)

_ESCAPE_SUBS = {
    '&': '&amp;',
    '>': '&gt;',
    '<': '&lt;',
    '"': '&quot;',
    "'": '&#x27;',
}

def escape(s):
    """Similar to html.escape()."""
    return charsub(s, _ESCAPE_SUBS)

_QUOTE_PLUS = {
    '\n':'%0A',
    '\r':'%0D',
    '"': '%22',
    '#': '%23',
    '%': '%25',
    '&': '%26',
    "'": '%27',
    '+': '%2B',
    '/': '%2F',
    ';': '%3B',
    '=': '%3D',
    '?': '%3F',
    ' ': '+',
}

def quote_plus(s, safe=''):
    """Similar to urllib.parse.quote_plus() but uses a blacklist for efficiency."""
    return charsub(s, _QUOTE_PLUS, safe)

def quote(s, safe='/'):
    """Similar to urllib.parse.quote() but uses a blacklist for efficiency."""
    s = charsub(s, _QUOTE_PLUS, safe)
    if '+' in s:
        s = s.replace('+', '%20')
    return s

def unquote(s):
    """Similar to urllib.parse.unquote(). Raises ValueError if unable to percent-decode."""
    if '%' not in s:
        return s
    parts = s.split('%')
    result = bytearray()
    result.extend(parts[0].encode())
    for item in parts[1:]:
        if len(item) < 2:
            raise ValueError()
        result.append(int(item[:2], 16))
        result.extend(item[2:].encode())
    return result.decode()

def unquote_plus(s):
    """Similar to urllib.parse.unquote_plus()."""
    if '+' in s:  # Avoid creating a new object if not necessary
        s = s.replace('+', ' ')
    return unquote(s)

def urlencode(data):
    """Similar to urllib.parse.urlencode()."""
    parts = []
    for key, val in data.items():
        if True:  # emulates quote_via=quote_plus
            key, val = quote_plus(key), quote_plus(val)
        if key:
            parts.append(key + '=' + val)
    return '&'.join(parts)

def urldecode(qs, maxpairs=None):
    """
    Similar to urllib.parse.parse_qs() but returns a simple dict, not a dict of lists.
    
    For example, urldecode('foo=1&bar=2&baz') returns {'foo': '1', 'bar': '2', 'baz': ''}.
    """
    data = {}
    if maxpairs is None:
        parts = qs.split('&')
    else:
        parts = qs.split('&', maxpairs)[:maxpairs]
    for part in parts:
        key, sep, val = part.partition('=')
        if True:
            key, val = unquote_plus(key), unquote_plus(val)
        if key:
            data[key] = val
    return data
