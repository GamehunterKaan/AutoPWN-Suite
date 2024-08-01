from typing import List, Optional, Union

DONT_SEARCH = {
    "ssh", "vnc", "http", "https", "ftp", "sftp", "smtp", "smb", "smbv2", 
    "httpd", "apache", "nginx", "linux telnetd", "microsoft windows rpc", 
    "metasploitable root shell", "gnu classpath grmiregistry", "server", 
    "service", "application", "software", "system", "device", "tool", 
    "utility", "daemon", "agent", "client", "remote", "desktop", "protocol", 
    "windows", "linux", "unix", "mac", "os", "operating", "system", 
    "microsoft", "apple", "gnu"
}

def generate_keyword_list_from_product(product: str, version: str) -> List[str]:
    """
    Generate a list of keywords from product and version strings.
    
    Args:
        product (str): The product name.
        version (str): The version name.
        
    Returns:
        List[str]: A list of keywords.
    """
    keywords = [f"{part} {version}" for part in product.split() if part.lower() not in DONT_SEARCH]
    print(f"Product: {product}, Version: {version}, Keywords: {keywords}")
    return keywords

def generate_keywords_from_cves(cves: List[str]) -> List[str]:
    """
    Generate keywords from a list of CVEs.
    
    Args:
        cves (List[str]): List of CVEs.
    
    Returns:
        List[str]: List of keywords generated from CVEs.
    """
    print(f"CVEs: {cves}")
    return cves

def generate_keywords_list_from_host_array(host_array: List[Union[List, tuple]], cves: Optional[List[str]] = None) -> List[str]:
    """
    Generate keywords from HostArray and optionally from a list of CVEs.
    
    Args:
        host_array (List[Union[List, tuple]]): List of host information.
        cves (Optional[List[str]]): List of CVEs.
    
    Returns:
        List[str]: List of keywords generated from HostArray and CVEs.
    """
    print(f"HostArray: {host_array}")
    keywords = set()
    if cves:
        keywords.update(cves)
    for port in host_array:
        if not isinstance(port, (list, tuple)) or len(port) < 5:
            continue
        product = str(port[3])
        version = str(port[4])

        new_keywords = generate_keyword_list_from_product(product, version)
        keywords.update(new_keywords)

    return list(keywords)

def generate_keywords(source: Union[str, List[Union[List, tuple]], List[str]], version: Optional[str] = None, cves: Optional[List[str]] = None) -> List[str]:
    """
    Generate keywords from different sources: product/version, CVEs, or host array.
    
    Args:
        source (Union[str, List[Union[List, tuple]], List[str]]): The source of keywords.
        version (Optional[str]): The version name if source is a product.
        cves (Optional[List[str]]): List of CVEs.
    
    Returns:
        List[str]: List of keywords generated from the source.
    """
    if isinstance(source, str) and version:
        # Source is a product with a version
        return generate_keyword_list_from_product(source, version)
    elif isinstance(source, list) and all(isinstance(item, str) for item in source):
        # Source is a list of CVEs
        return generate_keywords_from_cves(source)
    elif isinstance(source, list) and all(isinstance(item, (list, tuple)) for item in source):
        # Source is a host array
        return generate_keywords_list_from_host_array(source, cves)
    else:
        raise ValueError("Invalid source type")