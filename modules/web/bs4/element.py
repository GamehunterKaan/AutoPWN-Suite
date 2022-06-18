# Use of this source code is governed by the MIT license.
__license__ = "MIT"

try:
    from collections.abc import Callable # Python 3.6
except ImportError as e:
    from collections import Callable
import re
import sys
import warnings
try:
    import soupsieve
except ImportError as e:
    soupsieve = None
from modules.web.bs4.formatter import (
    Formatter,
    HTMLFormatter,
    XMLFormatter,
)

DEFAULT_OUTPUT_ENCODING = "utf-8"

nonwhitespace_re = re.compile(r"\S+")

# NOTE: This isn't used as of 4.7.0. I'm leaving it for a little bit on
# the off chance someone imported it for their own use.
whitespace_re = re.compile(r"\s+")

def _alias(attr):
    """Alias one attribute name to another for backward compatibility"""
    @property
    def alias(self):
        return getattr(self, attr)

    @alias.setter
    def alias(self):
        return setattr(self, attr)
    return alias

PYTHON_SPECIFIC_ENCODINGS = set([
    "idna",
    "mbcs",
    "oem",
    "palmos",
    "punycode",
    "raw_unicode_escape",
    "undefined",
    "unicode_escape",
    "raw-unicode-escape",
    "unicode-escape",
    "string-escape",
    "string_escape",
])
    

class NamespacedAttribute(str):
    """A namespaced string (e.g. 'xml:lang') that remembers the namespace
    ('xml') and the name ('lang') that were used to create it.
    """
    
    def __new__(cls, prefix, name=None, namespace=None):
        if not name:
            # This is the default namespace. Its name "has no value"
            # per https://www.w3.org/TR/xml-names/#defaulting
            name = None

        if not name:
            obj = str.__new__(cls, prefix)
        elif not prefix:
            # Not really namespaced.
            obj = str.__new__(cls, name)
        else:
            obj = str.__new__(cls, prefix + ":" + name)
        obj.prefix = prefix
        obj.name = name
        obj.namespace = namespace
        return obj

class AttributeValueWithCharsetSubstitution(str):
    """A stand-in object for a character encoding specified in HTML."""

class CharsetMetaAttributeValue(AttributeValueWithCharsetSubstitution):

    def __new__(cls, original_value):
        obj = str.__new__(cls, original_value)
        obj.original_value = original_value
        return obj

    def encode(self, encoding):

        if encoding in PYTHON_SPECIFIC_ENCODINGS:
            return ''
        return encoding


class ContentMetaAttributeValue(AttributeValueWithCharsetSubstitution):

    CHARSET_RE = re.compile(r"((^|;)\s*charset=)([^;]*)", re.M)

    def __new__(cls, original_value):
        match = cls.CHARSET_RE.search(original_value)
        if match is None:
            # No substitution necessary.
            return str.__new__(str, original_value)

        obj = str.__new__(cls, original_value)
        obj.original_value = original_value
        return obj

    def encode(self, encoding):
        if encoding in PYTHON_SPECIFIC_ENCODINGS:
            return ''
        def rewrite(match):
            return match.group(1) + encoding
        return self.CHARSET_RE.sub(rewrite, self.original_value)

    
class PageElement(object):

    def setup(self, parent=None, previous_element=None, next_element=None,
              previous_sibling=None, next_sibling=None):

        self.parent = parent

        self.previous_element = previous_element
        if previous_element is not None:
            self.previous_element.next_element = self

        self.next_element = next_element
        if self.next_element is not None:
            self.next_element.previous_element = self

        self.next_sibling = next_sibling
        if self.next_sibling is not None:
            self.next_sibling.previous_sibling = self

        if (previous_sibling is None
            and self.parent is not None and self.parent.contents):
            previous_sibling = self.parent.contents[-1]

        self.previous_sibling = previous_sibling
        if previous_sibling is not None:
            self.previous_sibling.next_sibling = self

    def format_string(self, s, formatter):

        if formatter is None:
            return s
        if not isinstance(formatter, Formatter):
            formatter = self.formatter_for_name(formatter)
        output = formatter.substitute(s)
        return output

    def formatter_for_name(self, formatter):

        if isinstance(formatter, Formatter):
            return formatter
        if self._is_xml:
            c = XMLFormatter
        else:
            c = HTMLFormatter
        if isinstance(formatter, Callable):
            return c(entity_substitution=formatter)
        return c.REGISTRY[formatter]

    @property
    def _is_xml(self):

        if self.known_xml is not None:

            return self.known_xml

        if self.parent is None:

            return getattr(self, 'is_xml', False)
        return self.parent._is_xml

    nextSibling = _alias("next_sibling")  # BS3
    previousSibling = _alias("previous_sibling")  # BS3

    default = object()
    def _all_strings(self, strip=False, types=default):

        raise NotImplementedError()
   
    @property
    def stripped_strings(self):

        for string in self._all_strings(True):
            yield string

    def get_text(self, separator="", strip=False,
                 types=default):

        return separator.join([s for s in self._all_strings(
                    strip, types=types)])
    getText = get_text
    text = property(get_text)
    
    def replace_with(self, *args):

        if self.parent is None:
            raise ValueError(
                "Cannot replace one element with another when the "
                "element to be replaced is not part of a tree.")
        if len(args) == 1 and args[0] is self:
            return
        if any(x is self.parent for x in args):
            raise ValueError("Cannot replace a Tag with its parent.")
        old_parent = self.parent
        my_index = self.parent.index(self)
        self.extract(_self_index=my_index)
        for idx, replace_with in enumerate(args, start=my_index):
            old_parent.insert(idx, replace_with)
        return self
    replaceWith = replace_with  # BS3

    def unwrap(self):

        my_parent = self.parent
        if self.parent is None:
            raise ValueError(
                "Cannot replace an element with its contents when that"
                "element is not part of a tree.")
        my_index = self.parent.index(self)
        self.extract(_self_index=my_index)
        for child in reversed(self.contents[:]):
            my_parent.insert(my_index, child)
        return self
    replace_with_children = unwrap
    replaceWithChildren = unwrap  # BS3

    def wrap(self, wrap_inside):

        me = self.replace_with(wrap_inside)
        wrap_inside.append(me)
        return wrap_inside

    def extract(self, _self_index=None):

        if self.parent is not None:
            if _self_index is None:
                _self_index = self.parent.index(self)
            del self.parent.contents[_self_index]

        last_child = self._last_descendant()
        next_element = last_child.next_element

        if (self.previous_element is not None and
            self.previous_element is not next_element):
            self.previous_element.next_element = next_element
        if next_element is not None and next_element is not self.previous_element:
            next_element.previous_element = self.previous_element
        self.previous_element = None
        last_child.next_element = None

        self.parent = None
        if (self.previous_sibling is not None
            and self.previous_sibling is not self.next_sibling):
            self.previous_sibling.next_sibling = self.next_sibling
        if (self.next_sibling is not None
            and self.next_sibling is not self.previous_sibling):
            self.next_sibling.previous_sibling = self.previous_sibling
        self.previous_sibling = self.next_sibling = None
        return self

    def _last_descendant(self, is_initialized=True, accept_self=True):

        if is_initialized and self.next_sibling is not None:
            last_child = self.next_sibling.previous_element
        else:
            last_child = self
            while isinstance(last_child, Tag) and last_child.contents:
                last_child = last_child.contents[-1]
        if not accept_self and last_child is self:
            last_child = None
        return last_child
    # BS3: Not part of the API!
    _lastRecursiveChild = _last_descendant

    def insert(self, position, new_child):

        if new_child is None:
            raise ValueError("Cannot insert None into a tag.")
        if new_child is self:
            raise ValueError("Cannot insert a tag into itself.")
        if (isinstance(new_child, str)
            and not isinstance(new_child, NavigableString)):
            new_child = NavigableString(new_child)

        from modules.web.bs4 import BeautifulSoup
        if isinstance(new_child, BeautifulSoup):

            for subchild in list(new_child.contents):
                self.insert(position, subchild)
                position += 1
            return
        position = min(position, len(self.contents))
        if hasattr(new_child, 'parent') and new_child.parent is not None:

            if new_child.parent is self:
                current_index = self.index(new_child)
                if current_index < position:

                    position -= 1
            new_child.extract()

        new_child.parent = self
        previous_child = None
        if position == 0:
            new_child.previous_sibling = None
            new_child.previous_element = self
        else:
            previous_child = self.contents[position - 1]
            new_child.previous_sibling = previous_child
            new_child.previous_sibling.next_sibling = new_child
            new_child.previous_element = previous_child._last_descendant(False)
        if new_child.previous_element is not None:
            new_child.previous_element.next_element = new_child

        new_childs_last_element = new_child._last_descendant(False)

        if position >= len(self.contents):
            new_child.next_sibling = None

            parent = self
            parents_next_sibling = None
            while parents_next_sibling is None and parent is not None:
                parents_next_sibling = parent.next_sibling
                parent = parent.parent
                if parents_next_sibling is not None:
                    # We found the element that comes next in the document.
                    break
            if parents_next_sibling is not None:
                new_childs_last_element.next_element = parents_next_sibling
            else:
                # The last element of this tag is the last element in
                # the document.
                new_childs_last_element.next_element = None
        else:
            next_child = self.contents[position]
            new_child.next_sibling = next_child
            if new_child.next_sibling is not None:
                new_child.next_sibling.previous_sibling = new_child
            new_childs_last_element.next_element = next_child

        if new_childs_last_element.next_element is not None:
            new_childs_last_element.next_element.previous_element = new_childs_last_element
        self.contents.insert(position, new_child)

    def append(self, tag):

        self.insert(len(self.contents), tag)

    def extend(self, tags):

        if isinstance(tags, Tag):
            # Calling self.append() on another tag's contents will change
            # the list we're iterating over. Make a list that won't
            # change.
            tags = list(tags.contents)
        for tag in tags:
            self.append(tag)

    def insert_before(self, *args):

        parent = self.parent
        if parent is None:
            raise ValueError(
                "Element has no parent, so 'before' has no meaning.")
        if any(x is self for x in args):
                raise ValueError("Can't insert an element before itself.")
        for predecessor in args:

            if isinstance(predecessor, PageElement):
                predecessor.extract()
            index = parent.index(self)
            parent.insert(index, predecessor)

    def insert_after(self, *args):

        parent = self.parent
        if parent is None:
            raise ValueError(
                "Element has no parent, so 'after' has no meaning.")
        if any(x is self for x in args):
            raise ValueError("Can't insert an element after itself.")
        
        offset = 0
        for successor in args:
            if isinstance(successor, PageElement):
                successor.extract()
            index = parent.index(self)
            parent.insert(index+1+offset, successor)
            offset += 1

    def find_next(self, name=None, attrs={}, string=None, **kwargs):

        return self._find_one(self.find_all_next, name, attrs, string, **kwargs)
    findNext = find_next  # BS3

    def find_all_next(self, name=None, attrs={}, string=None, limit=None,
                    **kwargs):

        return self._find_all(name, attrs, string, limit, self.next_elements,
                             **kwargs)
    findAllNext = find_all_next  # BS3

    def find_next_sibling(self, name=None, attrs={}, string=None, **kwargs):

        return self._find_one(self.find_next_siblings, name, attrs, string,
                             **kwargs)
    findNextSibling = find_next_sibling  # BS3

    def find_next_siblings(self, name=None, attrs={}, string=None, limit=None,
                           **kwargs):

        return self._find_all(name, attrs, string, limit,
                              self.next_siblings, **kwargs)
    findNextSiblings = find_next_siblings   # BS3
    fetchNextSiblings = find_next_siblings  # BS2

    def find_previous(self, name=None, attrs={}, string=None, **kwargs):

        return self._find_one(
            self.find_all_previous, name, attrs, string, **kwargs)
    findPrevious = find_previous  # BS3

    def find_all_previous(self, name=None, attrs={}, string=None, limit=None,
                        **kwargs):

        return self._find_all(name, attrs, string, limit, self.previous_elements,
                           **kwargs)
    findAllPrevious = find_all_previous  # BS3
    fetchPrevious = find_all_previous    # BS2

    def find_previous_sibling(self, name=None, attrs={}, string=None, **kwargs):

        return self._find_one(self.find_previous_siblings, name, attrs, string,
                             **kwargs)
    findPreviousSibling = find_previous_sibling  # BS3

    def find_previous_siblings(self, name=None, attrs={}, string=None,
                               limit=None, **kwargs):

        return self._find_all(name, attrs, string, limit,
                              self.previous_siblings, **kwargs)
    findPreviousSiblings = find_previous_siblings   # BS3
    fetchPreviousSiblings = find_previous_siblings  # BS2

    def find_parent(self, name=None, attrs={}, **kwargs):

        r = None
        l = self.find_parents(name, attrs, 1, **kwargs)
        if l:
            r = l[0]
        return r
    findParent = find_parent  # BS3

    def find_parents(self, name=None, attrs={}, limit=None, **kwargs):

        return self._find_all(name, attrs, None, limit, self.parents,
                             **kwargs)
    findParents = find_parents   # BS3
    fetchParents = find_parents  # BS2

    @property
    def next(self):

        return self.next_element

    @property
    def previous(self):

        return self.previous_element

    def _find_one(self, method, name, attrs, string, **kwargs):
        r = None
        l = method(name, attrs, string, 1, **kwargs)
        if l:
            r = l[0]
        return r

    def _find_all(self, name, attrs, string, limit, generator, **kwargs):
        "Iterates over a generator looking for things that match."

        if string is None and 'text' in kwargs:
            string = kwargs.pop('text')
            warnings.warn(
                "The 'text' argument to find()-type methods is deprecated. Use 'string' instead.",
                DeprecationWarning
            )

        if isinstance(name, SoupStrainer):
            strainer = name
        else:
            strainer = SoupStrainer(name, attrs, string, **kwargs)

        if string is None and not limit and not attrs and not kwargs:
            if name is True or name is None:
                # Optimization to find all tags.
                result = (element for element in generator
                          if isinstance(element, Tag))
                return ResultSet(strainer, result)
            elif isinstance(name, str):
                # Optimization to find all tags with a given name.
                if name.count(':') == 1:

                    prefix, local_name = name.split(':', 1)
                else:
                    prefix = None
                    local_name = name
                result = (element for element in generator
                          if isinstance(element, Tag)
                          and (
                              element.name == name
                          ) or (
                              element.name == local_name
                              and (prefix is None or element.prefix == prefix)
                          )
                )
                return ResultSet(strainer, result)
        results = ResultSet(strainer)
        while True:
            try:
                i = next(generator)
            except StopIteration:
                break
            if i:
                found = strainer.search(i)
                if found:
                    results.append(found)
                    if limit and len(results) >= limit:
                        break
        return results


    @property
    def next_elements(self):

        i = self.next_element
        while i is not None:
            yield i
            i = i.next_element

    @property
    def next_siblings(self):

        i = self.next_sibling
        while i is not None:
            yield i
            i = i.next_sibling

    @property
    def previous_elements(self):

        i = self.previous_element
        while i is not None:
            yield i
            i = i.previous_element

    @property
    def previous_siblings(self):

        i = self.previous_sibling
        while i is not None:
            yield i
            i = i.previous_sibling

    @property
    def parents(self):

        i = self.parent
        while i is not None:
            yield i
            i = i.parent

    @property
    def decomposed(self):
        return getattr(self, '_decomposed', False) or False

    def nextGenerator(self):
        return self.next_elements

    def nextSiblingGenerator(self):
        return self.next_siblings

    def previousGenerator(self):
        return self.previous_elements

    def previousSiblingGenerator(self):
        return self.previous_siblings

    def parentGenerator(self):
        return self.parents


class NavigableString(str, PageElement):

    PREFIX = ''
    SUFFIX = ''
    known_xml = None

    def __new__(cls, value):
        if isinstance(value, str):
            u = str.__new__(cls, value)
        else:
            u = str.__new__(cls, value, DEFAULT_OUTPUT_ENCODING)
        u.setup()
        return u

    def __copy__(self):
        return type(self)(self)

    def __getnewargs__(self):
        return (str(self),)

    def __getattr__(self, attr):
        if attr == 'string':
            return self
        else:
            raise AttributeError(
                "'%s' object has no attribute '%s'" % (
                    self.__class__.__name__, attr))

    def output_ready(self, formatter="minimal"):
        output = self.format_string(self, formatter)
        return self.PREFIX + output + self.SUFFIX

    @property
    def name(self):
        return None

    @name.setter
    def name(self, name):
        raise AttributeError("A NavigableString cannot be given a name.")

    def _all_strings(self, strip=False, types=PageElement.default):
        if types is self.default:
            types = Tag.DEFAULT_INTERESTING_STRING_TYPES
        my_type = type(self)
        if types is not None:
            if isinstance(types, type):
                # Looking for a single type.
                if my_type is not types:
                    return
            elif my_type not in types:
                # Looking for one of a list of types.
                return

        value = self
        if strip:
            value = value.strip()
        if len(value) > 0:
            yield value
    strings = property(_all_strings)

class PreformattedString(NavigableString):

    PREFIX = ''
    SUFFIX = ''
    
    def output_ready(self, formatter=None):

        if formatter is not None:
            ignore = self.format_string(self, formatter)
        return self.PREFIX + self + self.SUFFIX

class CData(PreformattedString):
    """A CDATA block."""
    PREFIX = '<![CDATA['
    SUFFIX = ']]>'

class ProcessingInstruction(PreformattedString):
    """A SGML processing instruction."""

    PREFIX = '<?'
    SUFFIX = '>'

class XMLProcessingInstruction(ProcessingInstruction):
    """An XML processing instruction."""
    PREFIX = '<?'
    SUFFIX = '?>'

class Comment(PreformattedString):
    """An HTML or XML comment."""
    PREFIX = '<!--'
    SUFFIX = '-->'


class Declaration(PreformattedString):
    """An XML declaration."""
    PREFIX = '<?'
    SUFFIX = '?>'


class Doctype(PreformattedString):
    @classmethod
    def for_name_and_ids(cls, name, pub_id, system_id):

        value = name or ''
        if pub_id is not None:
            value += ' PUBLIC "%s"' % pub_id
            if system_id is not None:
                value += ' "%s"' % system_id
        elif system_id is not None:
            value += ' SYSTEM "%s"' % system_id

        return Doctype(value)

    PREFIX = '<!DOCTYPE '
    SUFFIX = '>\n'


class Stylesheet(NavigableString):
    pass

    
class Script(NavigableString):
    pass


class TemplateString(NavigableString):
    pass


class RubyTextString(NavigableString):
    pass


class RubyParenthesisString(NavigableString):
    pass


class Tag(PageElement):
    def __init__(self, parser=None, builder=None, name=None, namespace=None,
                 prefix=None, attrs=None, parent=None, previous=None,
                 is_xml=None, sourceline=None, sourcepos=None,
                 can_be_empty_element=None, cdata_list_attributes=None,
                 preserve_whitespace_tags=None,
                 interesting_string_types=None,
                 namespaces=None
    ):
        if parser is None:
            self.parser_class = None
        else:
            self.parser_class = parser.__class__
        if name is None:
            raise ValueError("No value provided for new tag's name.")
        self.name = name
        self.namespace = namespace
        self._namespaces = namespaces or {}
        self.prefix = prefix
        if ((not builder or builder.store_line_numbers)
            and (sourceline is not None or sourcepos is not None)):
            self.sourceline = sourceline
            self.sourcepos = sourcepos        
        if attrs is None:
            attrs = {}
        elif attrs:
            if builder is not None and builder.cdata_list_attributes:
                attrs = builder._replace_cdata_list_attribute_values(
                    self.name, attrs)
            else:
                attrs = dict(attrs)
        else:
            attrs = dict(attrs)

        if builder:
            self.known_xml = builder.is_xml
        else:
            self.known_xml = is_xml
        self.attrs = attrs
        self.contents = []
        self.setup(parent, previous)
        self.hidden = False

        if builder is None:
            self.can_be_empty_element = can_be_empty_element
            self.cdata_list_attributes = cdata_list_attributes
            self.preserve_whitespace_tags = preserve_whitespace_tags
            self.interesting_string_types = interesting_string_types
        else:
            builder.set_up_substitutions(self)
            self.can_be_empty_element = builder.can_be_empty_element(name)
            self.cdata_list_attributes = builder.cdata_list_attributes
            self.preserve_whitespace_tags = builder.preserve_whitespace_tags

            if self.name in builder.string_containers:
                self.interesting_string_types = builder.string_containers[self.name]
            else:
                self.interesting_string_types = self.DEFAULT_INTERESTING_STRING_TYPES
            
    parserClass = _alias("parser_class")  # BS3

    def __copy__(self):
        clone = type(self)(
            None, self.builder, self.name, self.namespace,
            self.prefix, self.attrs, is_xml=self._is_xml,
            sourceline=self.sourceline, sourcepos=self.sourcepos,
            can_be_empty_element=self.can_be_empty_element,
            cdata_list_attributes=self.cdata_list_attributes,
            preserve_whitespace_tags=self.preserve_whitespace_tags
        )
        for attr in ('can_be_empty_element', 'hidden'):
            setattr(clone, attr, getattr(self, attr))
        for child in self.contents:
            clone.append(child.__copy__())
        return clone
    
    @property
    def is_empty_element(self):
        return len(self.contents) == 0 and self.can_be_empty_element
    isSelfClosing = is_empty_element  # BS3

    @property
    def string(self):
        if len(self.contents) != 1:
            return None
        child = self.contents[0]
        if isinstance(child, NavigableString):
            return child
        return child.string

    @string.setter
    def string(self, string):
        self.clear()
        self.append(string.__class__(string))

    DEFAULT_INTERESTING_STRING_TYPES = (NavigableString, CData)
    def _all_strings(self, strip=False, types=PageElement.default):
        if types is self.default:
            types = self.interesting_string_types

        for descendant in self.descendants:
            if (types is None and not isinstance(descendant, NavigableString)):
                continue
            descendant_type = type(descendant)
            if isinstance(types, type):
                if descendant_type is not types:
                    # We're not interested in strings of this type.
                    continue
            elif types is not None and descendant_type not in types:
                # We're not interested in strings of this type.
                continue
            if strip:
                descendant = descendant.strip()
                if len(descendant) == 0:
                    continue
            yield descendant
    strings = property(_all_strings)

    def decompose(self):
        self.extract()
        i = self
        while i is not None:
            n = i.next_element
            i.__dict__.clear()
            i.contents = []
            i._decomposed = True
            i = n
           
    def clear(self, decompose=False):
        if decompose:
            for element in self.contents[:]:
                if isinstance(element, Tag):
                    element.decompose()
                else:
                    element.extract()
        else:
            for element in self.contents[:]:
                element.extract()

    def smooth(self):
        marked = []
        for i, a in enumerate(self.contents):
            if isinstance(a, Tag):
                # Recursively smooth children.
                a.smooth()
            if i == len(self.contents)-1:
                # This is the last item in .contents, and it's not a
                # tag. There's no chance it needs any work.
                continue
            b = self.contents[i+1]
            if (isinstance(a, NavigableString)
                and isinstance(b, NavigableString)
                and not isinstance(a, PreformattedString)
                and not isinstance(b, PreformattedString)
            ):
                marked.append(i)
        for i in reversed(marked):
            a = self.contents[i]
            b = self.contents[i+1]
            b.extract()
            n = NavigableString(a+b)
            a.replace_with(n)

    def index(self, element):
        for i, child in enumerate(self.contents):
            if child is element:
                return i
        raise ValueError("Tag.index: element not in tag")

    def get(self, key, default=None):
        return self.attrs.get(key, default)

    def get_attribute_list(self, key, default=None):
        value = self.get(key, default)
        if not isinstance(value, list):
            value = [value]
        return value
    
    def has_attr(self, key):
        return key in self.attrs

    def __hash__(self):
        return str(self).__hash__()

    def __getitem__(self, key):
        return self.attrs[key]

    def __iter__(self):
        return iter(self.contents)

    def __len__(self):
        return len(self.contents)

    def __contains__(self, x):
        return x in self.contents

    def __bool__(self):
        "A tag is non-None even if it has no contents."
        return True

    def __setitem__(self, key, value):
        """Setting tag[key] sets the value of the 'key' attribute for the
        tag."""
        self.attrs[key] = value

    def __delitem__(self, key):
        "Deleting tag[key] deletes all 'key' attributes for the tag."
        self.attrs.pop(key, None)

    def __call__(self, *args, **kwargs):
        return self.find_all(*args, **kwargs)

    def __getattr__(self, tag):
        if len(tag) > 3 and tag.endswith('Tag'):
            # BS3: soup.aTag -> "soup.find("a")
            tag_name = tag[:-3]
            warnings.warn(
                '.%(name)sTag is deprecated, use .find("%(name)s") instead. If you really were looking for a tag called %(name)sTag, use .find("%(name)sTag")' % dict(
                    name=tag_name
                ),
                DeprecationWarning
            )
            return self.find(tag_name)
        # We special case contents to avoid recursion.
        elif not tag.startswith("__") and not tag == "contents":
            return self.find(tag)
        raise AttributeError(
            "'%s' object has no attribute '%s'" % (self.__class__, tag))

    def __eq__(self, other):
        if self is other:
            return True
        if (not hasattr(other, 'name') or
            not hasattr(other, 'attrs') or
            not hasattr(other, 'contents') or
            self.name != other.name or
            self.attrs != other.attrs or
            len(self) != len(other)):
            return False
        for i, my_child in enumerate(self.contents):
            if my_child != other.contents[i]:
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def __repr__(self, encoding="unicode-escape"):
        return self.decode()

    def __unicode__(self):
        """Renders this PageElement as a Unicode string."""
        return self.decode()

    __str__ = __repr__ = __unicode__

    def encode(self, encoding=DEFAULT_OUTPUT_ENCODING,
               indent_level=None, formatter="minimal",
               errors="xmlcharrefreplace"):
        u = self.decode(indent_level, encoding, formatter)
        return u.encode(encoding, errors)

    def decode(self, indent_level=None,
               eventual_encoding=DEFAULT_OUTPUT_ENCODING,
               formatter="minimal"):
        if not isinstance(formatter, Formatter):
            formatter = self.formatter_for_name(formatter)
        attributes = formatter.attributes(self)
        attrs = []
        for key, val in attributes:
            if val is None:
                decoded = key
            else:
                if isinstance(val, list) or isinstance(val, tuple):
                    val = ' '.join(val)
                elif not isinstance(val, str):
                    val = str(val)
                elif (
                        isinstance(val, AttributeValueWithCharsetSubstitution)
                        and eventual_encoding is not None
                ):
                    val = val.encode(eventual_encoding)

                text = formatter.attribute_value(val)
                decoded = (
                    str(key) + '='
                    + formatter.quoted_attribute_value(text))
            attrs.append(decoded)
        close = ''
        closeTag = ''

        prefix = ''
        if self.prefix:
            prefix = self.prefix + ":"

        if self.is_empty_element:
            close = formatter.void_element_close_prefix or ''
        else:
            closeTag = '</%s%s>' % (prefix, self.name)

        pretty_print = self._should_pretty_print(indent_level)
        space = ''
        indent_space = ''
        if indent_level is not None:
            indent_space = (formatter.indent * (indent_level - 1))
        if pretty_print:
            space = indent_space
            indent_contents = indent_level + 1
        else:
            indent_contents = None
        contents = self.decode_contents(
            indent_contents, eventual_encoding, formatter
        )

        if self.hidden:
            # This is the 'document root' object.
            s = contents
        else:
            s = []
            attribute_string = ''
            if attrs:
                attribute_string = ' ' + ' '.join(attrs)
            if indent_level is not None:
                # Even if this particular tag is not pretty-printed,
                # we should indent up to the start of the tag.
                s.append(indent_space)
            s.append('<%s%s%s%s>' % (
                    prefix, self.name, attribute_string, close))
            if pretty_print:
                s.append("\n")
            s.append(contents)
            if pretty_print and contents and contents[-1] != "\n":
                s.append("\n")
            if pretty_print and closeTag:
                s.append(space)
            s.append(closeTag)
            if indent_level is not None and closeTag and self.next_sibling:
                s.append("\n")
            s = ''.join(s)
        return s

    def _should_pretty_print(self, indent_level):
        return (
            indent_level is not None
            and (
                not self.preserve_whitespace_tags
                or self.name not in self.preserve_whitespace_tags
            )
        )

    def prettify(self, encoding=None, formatter="minimal"):
        if encoding is None:
            return self.decode(True, formatter=formatter)
        else:
            return self.encode(encoding, True, formatter=formatter)

    def decode_contents(self, indent_level=None,
                       eventual_encoding=DEFAULT_OUTPUT_ENCODING,
                       formatter="minimal"):
        if not isinstance(formatter, Formatter):
            formatter = self.formatter_for_name(formatter)

        pretty_print = (indent_level is not None)
        s = []
        for c in self:
            text = None
            if isinstance(c, NavigableString):
                text = c.output_ready(formatter)
            elif isinstance(c, Tag):
                s.append(c.decode(indent_level, eventual_encoding,
                                  formatter))
            preserve_whitespace = (
                self.preserve_whitespace_tags and self.name in self.preserve_whitespace_tags
            )
            if text and indent_level and not preserve_whitespace:
                text = text.strip()
            if text:
                if pretty_print and not preserve_whitespace:
                    s.append(formatter.indent * (indent_level - 1))
                s.append(text)
                if pretty_print and not preserve_whitespace:
                    s.append("\n")
        return ''.join(s)
       
    def encode_contents(
        self, indent_level=None, encoding=DEFAULT_OUTPUT_ENCODING,
        formatter="minimal"):
        contents = self.decode_contents(indent_level, encoding, formatter)
        return contents.encode(encoding)

    # Old method for BS3 compatibility
    def renderContents(self, encoding=DEFAULT_OUTPUT_ENCODING,
                       prettyPrint=False, indentLevel=0):
        """Deprecated method for BS3 compatibility."""
        if not prettyPrint:
            indentLevel = None
        return self.encode_contents(
            indent_level=indentLevel, encoding=encoding)

    #Soup methods

    def find(self, name=None, attrs={}, recursive=True, string=None,
             **kwargs):
        r = None
        l = self.find_all(name, attrs, recursive, string, 1, **kwargs)
        if l:
            r = l[0]
        return r
    findChild = find #BS2

    def find_all(self, name=None, attrs={}, recursive=True, string=None,
                 limit=None, **kwargs):
        generator = self.descendants
        if not recursive:
            generator = self.children
        return self._find_all(name, attrs, string, limit, generator, **kwargs)
    findAll = find_all       # BS3
    findChildren = find_all  # BS2

    #Generator methods
    @property
    def children(self):
        return iter(self.contents)  # XXX This seems to be untested.

    @property
    def descendants(self):
        if not len(self.contents):
            return
        stopNode = self._last_descendant().next_element
        current = self.contents[0]
        while current is not stopNode:
            yield current
            current = current.next_element

    # CSS selector code
    def select_one(self, selector, namespaces=None, **kwargs):
        value = self.select(selector, namespaces, 1, **kwargs)
        if value:
            return value[0]
        return None

    def select(self, selector, namespaces=None, limit=None, **kwargs):
        if namespaces is None:
            namespaces = self._namespaces
        
        if limit is None:
            limit = 0
        if soupsieve is None:
            raise NotImplementedError(
                "Cannot execute CSS selectors because the soupsieve package is not installed."
            )
            
        results = soupsieve.select(selector, self, namespaces, limit, **kwargs)

        # We do this because it's more consistent and because
        # ResultSet.__getattr__ has a helpful error message.
        return ResultSet(None, results)

    # Old names for backwards compatibility
    def childGenerator(self):
        """Deprecated generator."""
        return self.children

    def recursiveChildGenerator(self):
        """Deprecated generator."""
        return self.descendants

    def has_key(self, key):
        warnings.warn(
            'has_key is deprecated. Use has_attr(key) instead.',
            DeprecationWarning
        )
        return self.has_attr(key)

# Next, a couple classes to represent queries and their results.
class SoupStrainer(object):
    def __init__(self, name=None, attrs={}, string=None, **kwargs):
        if string is None and 'text' in kwargs:
            string = kwargs.pop('text')
            warnings.warn(
                "The 'text' argument to the SoupStrainer constructor is deprecated. Use 'string' instead.",
                DeprecationWarning
            )

        self.name = self._normalize_search_value(name)
        if not isinstance(attrs, dict):
            # Treat a non-dict value for attrs as a search for the 'class'
            # attribute.
            kwargs['class'] = attrs
            attrs = None

        if 'class_' in kwargs:
            # Treat class_="foo" as a search for the 'class'
            # attribute, overriding any non-dict value for attrs.
            kwargs['class'] = kwargs['class_']
            del kwargs['class_']

        if kwargs:
            if attrs:
                attrs = attrs.copy()
                attrs.update(kwargs)
            else:
                attrs = kwargs
        normalized_attrs = {}
        for key, value in list(attrs.items()):
            normalized_attrs[key] = self._normalize_search_value(value)

        self.attrs = normalized_attrs
        self.string = self._normalize_search_value(string)

        # DEPRECATED but just in case someone is checking this.
        self.text = self.string

    def _normalize_search_value(self, value):
        if (isinstance(value, str) or isinstance(value, Callable) or hasattr(value, 'match')
            or isinstance(value, bool) or value is None):
            return value

        # If it's a bytestring, convert it to Unicode, treating it as UTF-8.
        if isinstance(value, bytes):
            return value.decode("utf8")

        # If it's listlike, convert it into a list of strings.
        if hasattr(value, '__iter__'):
            new_value = []
            for v in value:
                if (hasattr(v, '__iter__') and not isinstance(v, bytes)
                    and not isinstance(v, str)):
                    new_value.append(v)
                else:
                    new_value.append(self._normalize_search_value(v))
            return new_value

        # Otherwise, convert it into a Unicode string.
        # The unicode(str()) thing is so this will do the same thing on Python 2
        # and Python 3.
        return str(str(value))

    def __str__(self):
        """A human-readable representation of this SoupStrainer."""
        if self.string:
            return self.string
        else:
            return "%s|%s" % (self.name, self.attrs)

    def search_tag(self, markup_name=None, markup_attrs={}):
        found = None
        markup = None
        if isinstance(markup_name, Tag):
            markup = markup_name
            markup_attrs = markup

        if isinstance(self.name, str):
            if markup and not markup.prefix and self.name != markup.name:
                 return False
            
        call_function_with_tag_data = (
            isinstance(self.name, Callable)
            and not isinstance(markup_name, Tag))

        if ((not self.name)
            or call_function_with_tag_data
            or (markup and self._matches(markup, self.name))
            or (not markup and self._matches(markup_name, self.name))):
            if call_function_with_tag_data:
                match = self.name(markup_name, markup_attrs)
            else:
                match = True
                markup_attr_map = None
                for attr, match_against in list(self.attrs.items()):
                    if not markup_attr_map:
                        if hasattr(markup_attrs, 'get'):
                            markup_attr_map = markup_attrs
                        else:
                            markup_attr_map = {}
                            for k, v in markup_attrs:
                                markup_attr_map[k] = v
                    attr_value = markup_attr_map.get(attr)
                    if not self._matches(attr_value, match_against):
                        match = False
                        break
            if match:
                if markup:
                    found = markup
                else:
                    found = markup_name
        if found and self.string and not self._matches(found.string, self.string):
            found = None
        return found

    # For BS3 compatibility.
    searchTag = search_tag

    def search(self, markup):
        found = None
        # If given a list of items, scan it for a text element that
        # matches.
        if hasattr(markup, '__iter__') and not isinstance(markup, (Tag, str)):
            for element in markup:
                if isinstance(element, NavigableString) \
                       and self.search(element):
                    found = element
                    break
        # If it's a Tag, make sure its name or attributes match.
        # Don't bother with Tags if we're searching for text.
        elif isinstance(markup, Tag):
            if not self.string or self.name or self.attrs:
                found = self.search_tag(markup)
        # If it's text, make sure the text matches.
        elif isinstance(markup, NavigableString) or \
                 isinstance(markup, str):
            if not self.name and not self.attrs and self._matches(markup, self.string):
                found = markup
        else:
            raise Exception(
                "I don't know how to match against a %s" % markup.__class__)
        return found

    def _matches(self, markup, match_against, already_tried=None):
        # print(u"Matching %s against %s" % (markup, match_against))
        result = False
        if isinstance(markup, list) or isinstance(markup, tuple):
            # This should only happen when searching a multi-valued attribute
            # like 'class'.
            for item in markup:
                if self._matches(item, match_against):
                    return True
            if self._matches(' '.join(markup), match_against):
                return True
            return False
        
        if match_against is True:
            # True matches any non-None value.
            return markup is not None

        if isinstance(match_against, Callable):
            return match_against(markup)

        # Custom callables take the tag as an argument, but all
        # other ways of matching match the tag name as a string.
        original_markup = markup
        if isinstance(markup, Tag):
            markup = markup.name

        # Ensure that `markup` is either a Unicode string, or None.
        markup = self._normalize_search_value(markup)

        if markup is None:
            # None matches None, False, an empty string, an empty list, and so on.
            return not match_against

        if (hasattr(match_against, '__iter__')
            and not isinstance(match_against, str)):
            if not already_tried:
                already_tried = set()
            for item in match_against:
                if item.__hash__:
                    key = item
                else:
                    key = id(item)
                if key in already_tried:
                    continue
                else:
                    already_tried.add(key)
                    if self._matches(original_markup, item, already_tried):
                        return True
            else:
                return False
        match = False
        
        if not match and isinstance(match_against, str):
            # Exact string match
            match = markup == match_against

        if not match and hasattr(match_against, 'search'):
            # Regexp match
            return match_against.search(markup)

        if (not match
            and isinstance(original_markup, Tag)
            and original_markup.prefix):
            # Try the whole thing again with the prefixed tag name.
            return self._matches(
                original_markup.prefix + ':' + original_markup.name, match_against
            )

        return match


class ResultSet(list):
    def __init__(self, source, result=()):
        super(ResultSet, self).__init__(result)
        self.source = source

    def __getattr__(self, key):
        raise AttributeError(
            "ResultSet object has no attribute '%s'. You're probably treating a list of elements like a single element. Did you call find_all() when you meant to call find()?" % key
        )
