from typing import List, Optional, Union

import openai

DONT_SEARCH = {
    "ssh", "vnc", "http", "https", "ftp", "sftp", "smtp", "smb", "smbv2", 
    "httpd", "apache", "nginx", "linux telnetd", "microsoft windows rpc", 
    "metasploitable root shell", "gnu classpath grmiregistry", "server", 
    "service", "application", "software", "system", "device", "tool", 
    "utility", "daemon", "agent", "client", "remote", "desktop", "protocol", 
    "windows", "linux", "unix", "mac", "os", "operating", "system", 
    "microsoft", "apple", "gnu", "none", "unknown", "", 
}

def generate_keyword_list_from_product(product: str, version: str, seen_products: set) -> List[str]:
    """
    Generate a list of keywords from product and version strings.
    
    Args:
        product (str): The product name.
        version (str): The version name.
        seen_products (set): Set of already seen products.
        
    Returns:
        List[str]: A list of keywords.
    """
    product_key = f"{product.lower()} {version.lower()}"
    if product_key in seen_products:
        return []
    
    keywords = [
        f"{part} {version}" for part in product.split()
        if part.lower() not in DONT_SEARCH and not part.replace('.', '', 1).isdigit()
    ]
    
    if version.lower() not in DONT_SEARCH and not version.replace('.', '', 1).isdigit():
        keywords.append(version)
    
    seen_products.add(product_key)
    return keywords

def generate_keywords_from_cves(cves: List[str]) -> List[str]:
    """
    Generate keywords from a list of CVEs.
    
    Args:
        cves (List[str]): List of CVEs.
    
    Returns:
        List[str]: List of keywords generated from CVEs.
    """
    return cves

def generate_keywords_list_from_host_array(host_array: List[Union[List, tuple]], cves: Optional[List[str]] = None, openai_api_key: Optional[str] = None) -> List[str]:
    """
    Generate keywords from HostArray and optionally from a list of CVEs.
    
    Args:
        host_array (List[Union[List, tuple]]): List of host information.
        cves (Optional[List[str]]): List of CVEs.
    
    Returns:
        List[str]: List of keywords generated from HostArray and CVEs.
    """
    keywords = set()
    seen_products = set()
    
    if cves:
        keywords.update(cves)
    
    for port in host_array:
        if not isinstance(port, (list, tuple)) or len(port) < 5:
            continue
        product = str(port[2])  # Adjusted to use the correct product field
        version = str(port[4])

        if openai_api_key:
            new_keywords = generate_keywords_with_ai(openai_api_key, product, version, cves)
        else:
            new_keywords = generate_keyword_list_from_product(product, version, seen_products)
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
    all_keywords = set()
    seen_products = set()
    
    if isinstance(source, str) and version:
        # Source is a product with a version
        all_keywords.update(generate_keyword_list_from_product(source, version, seen_products))
    elif isinstance(source, list) and all(isinstance(item, str) for item in source):
        # Source is a list of CVEs
        all_keywords.update(generate_keywords_from_cves(source))
    elif isinstance(source, list) and all(isinstance(item, (list, tuple)) for item in source):
        # Source is a host array
        all_keywords.update(generate_keywords_list_from_host_array(source, cves))
    else:
        raise ValueError("Invalid source type")
    
    return list(all_keywords)

def generate_keywords_with_ai(api_key: str, source: Union[str, List[Union[List, tuple]], List[str]], version: Optional[str] = None, cves: Optional[List[str]] = None) -> List[str]:
    """
    Generate keywords from different sources by sending all the data to the OpenAI model.
    
    Args:
        api_key (str): The OpenAI API key.
        source (Union[str, List[Union[List, tuple]], List[str]]): The source of keywords.
        version (Optional[str]): The version name if source is a product.
        cves (Optional[List[str]]): List of CVEs.
    
    Returns:
        List[str]: List of generated keywords.
    """
    openai.api_key = api_key
    
    # Create a detailed prompt based on the input data
    prompt_parts = ["Generate a list of relevant keywords based on the following data:"]
    
    if isinstance(source, str) and version:
        prompt_parts.append(f"Product: {source}, Version: {version}")
    
    if isinstance(source, list) and all(isinstance(item, str) for item in source):
        prompt_parts.append(f"CVEs: {', '.join(source)}")
    
    if isinstance(source, list) and all(isinstance(item, (list, tuple)) for item in source):
        for port_info in source:
            if len(port_info) >= 5:
                port, proto, product, service, version = port_info[:5]
                prompt_parts.append(f"Port: {port}, Protocol: {proto}, Product: {product}, Service: {service}, Version: {version}")
    
    if cves:
        prompt_parts.append(f"Additional CVEs: {', '.join(cves)}")
    
    prompt = "\n".join(prompt_parts)
    
    # Send the prompt to the OpenAI API
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": prompt}
        ],
    )
    
    # Extract and return the keywords from the response
    keywords = response.choices[0].message.content.strip().split(', ')
    return keywords
