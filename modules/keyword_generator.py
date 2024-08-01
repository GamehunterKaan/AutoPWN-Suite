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

    if CVEs:
        keywords.extend(GenerateKeywordsFromCVEs(CVEs))

    return keywords

def GenerateKeywordsFromCVEs(CVEs: List[str]) -> List[str]:
    """
    Generate keywords from a list of CVEs.
    
    Args:
        CVEs (List[str]): List of CVEs.
    
    Returns:
        List[str]: List of keywords generated from CVEs.
    """
    keywords = []
    for cve in CVEs:
        # Extract keywords from CVE (e.g., CVE-2021-12345 -> 2021, 12345)
        parts = re.findall(r'\d+', cve)
        keywords.extend(parts)
    
    return keywords

def GenerateKeywords(HostArray: List, CVEs: List[str] = None) -> List[str]:
    keywords = []
    for port in HostArray:
        product = str(port[3])
        version = str(port[4])

        new_keywords = GenerateKeywordList(product, version)
        keywords.extend(new_keywords)

    return keywords

