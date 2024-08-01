from typing import List
import re

def GenerateKeywordList(product: str, version: str) -> List[str]:
    if product == "Unknown":
        product = ""

    if version == "Unknown":
        version = ""

    keywords = []
    dontsearch = [
        "ssh",
        "vnc",
        "http",
        "https",
        "ftp",
        "sftp",
        "smtp",
        "smb",
        "smbv2",
        "linux telnetd",
        "microsoft windows rpc",
        "metasploitable root shell",
        "gnu classpath grmiregistry",
        "server",
        "service",
        "application",
        "software",
        "system",
        "device",
        "tool",
        "utility",
        "daemon",
        "agent",
        "client",
        "remote",
        "desktop",
        "protocol",
        "server",
        "service",
        "application",
        "software",
        "system",
        "device",
        "tool",
        "utility",
        "daemon",
        "agent",
        "client",
    ]

    product_parts = product.split()
    for part in product_parts:
        if part.lower() not in dontsearch and part != "":
            keywords.append(part)

    return keywords

def GenerateKeywords(HostArray: List) -> List[str]:
    keywords = []
    for port in HostArray:
        product = str(port[3])
        version = str(port[4])

        new_keywords = GenerateKeywordList(product, version)
        keywords.extend(new_keywords)

    return keywords

