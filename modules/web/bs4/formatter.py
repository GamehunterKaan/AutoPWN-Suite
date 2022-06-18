from modules.web.bs4.dammit import EntitySubstitution

class Formatter(EntitySubstitution):
    XML_FORMATTERS = {}
    HTML_FORMATTERS = {}

    HTML = 'html'
    XML = 'xml'

    HTML_DEFAULTS = dict(
        cdata_containing_tags=set(["script", "style"]),
    )

    def _default(self, language, value, kwarg):
        if value is not None:
            return value
        if language == self.XML:
            return set()
        return self.HTML_DEFAULTS[kwarg]

    def __init__(
            self, language=None, entity_substitution=None,
            void_element_close_prefix='/', cdata_containing_tags=None,
            empty_attributes_are_booleans=False, indent=1,
    ):
        self.language = language
        self.entity_substitution = entity_substitution
        self.void_element_close_prefix = void_element_close_prefix
        self.cdata_containing_tags = self._default(
            language, cdata_containing_tags, 'cdata_containing_tags'
        )
        self.empty_attributes_are_booleans=empty_attributes_are_booleans
        if indent is None:
            indent = 0
        if isinstance(indent, int):
            if indent < 0:
                indent = 0
            indent = ' ' * indent
        elif isinstance(indent, str):
            indent = indent
        else:
            indent = ' '
        self.indent = indent
        
    def substitute(self, ns):
        if not self.entity_substitution:
            return ns
        from .element import NavigableString
        if (isinstance(ns, NavigableString)
            and ns.parent is not None
            and ns.parent.name in self.cdata_containing_tags):
            # Do nothing.
            return ns
        # Substitute.
        return self.entity_substitution(ns)

    def attribute_value(self, value):
        return self.substitute(value)
    
    def attributes(self, tag):
        if tag.attrs is None:
            return []
        return sorted(
            (k, (None if self.empty_attributes_are_booleans and v == '' else v))
            for k, v in list(tag.attrs.items())
        )
   
class HTMLFormatter(Formatter):
    """A generic Formatter for HTML."""
    REGISTRY = {}
    def __init__(self, *args, **kwargs):
        return super(HTMLFormatter, self).__init__(self.HTML, *args, **kwargs)

    
class XMLFormatter(Formatter):
    """A generic Formatter for XML."""
    REGISTRY = {}
    def __init__(self, *args, **kwargs):
        return super(XMLFormatter, self).__init__(self.XML, *args, **kwargs)


# Set up aliases for the default formatters.
HTMLFormatter.REGISTRY['html'] = HTMLFormatter(
    entity_substitution=EntitySubstitution.substitute_html
)
HTMLFormatter.REGISTRY["html5"] = HTMLFormatter(
    entity_substitution=EntitySubstitution.substitute_html,
    void_element_close_prefix=None,
    empty_attributes_are_booleans=True,
)
HTMLFormatter.REGISTRY["minimal"] = HTMLFormatter(
    entity_substitution=EntitySubstitution.substitute_xml
)
HTMLFormatter.REGISTRY[None] = HTMLFormatter(
    entity_substitution=None
)
XMLFormatter.REGISTRY["html"] =  XMLFormatter(
    entity_substitution=EntitySubstitution.substitute_html
)
XMLFormatter.REGISTRY["minimal"] = XMLFormatter(
    entity_substitution=EntitySubstitution.substitute_xml
)
XMLFormatter.REGISTRY[None] = Formatter(
    Formatter(Formatter.XML, entity_substitution=None)
)
