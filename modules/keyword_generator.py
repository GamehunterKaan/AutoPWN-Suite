import re
from typing import List


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

def GenerateKeywords(HostArray: List, CVEs: List[str] = None) -> List[str]:
    keywords = []
    if CVEs:
        keywords.extend(GenerateKeywordsFromCVEs(CVEs))
        
    for port in HostArray:
        if not isinstance(port, (list, tuple)) or len(port) < 5:
            continue
        if len(port) < 5:
            continue
        product = str(port[3])
        version = str(port[4])

        new_keywords = GenerateKeywordList(product, version)
        keywords.extend(new_keywords)

    return keywords

def GenerateKeywordsFromCVEs(CVEs: List[str]) -> List[str]:
    """
    Generate keywords from a list of CVEs.
    
    Args:
        CVEs (List[str]): List of CVEs.
    
    Returns:
        List[str]: List of keywords generated from CVEs.
    """
    return CVEs

def GenerateKeywords(HostArray: List, CVEs: List[str] = None) -> List[str]:
    keywords = []
    if CVEs:
        keywords.extend(GenerateKeywordsFromCVEs(CVEs))
        
    for port in HostArray:
        if not isinstance(port, (list, tuple)) or len(port) < 5:
            continue
        product = str(port[3])
        version = str(port[4])

        new_keywords = GenerateKeywordList(product, version)
        keywords.extend(new_keywords)

    return keywords

