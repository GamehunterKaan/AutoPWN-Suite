import requests
from modules.web.bs4 import BeautifulSoup # https://pypi.org/project/beautifulsoup4/


def crawl(target_url):
    if not target_url.endswith('/'):
        target_url += '/'
    urls = []
    reqs = requests.get(target_url)
    soup = BeautifulSoup(reqs.text, 'html.parser')

    for link in soup.find_all('a'):
        url = link.get('href')
        if not url.startswith('http'):
            if url.startswith('./'):
                url = target_url + url.lstrip('./')
            elif url.startswith('/'):
                url = target_url + url.lstrip('/')
            elif "#" in url:
                continue
            elif url == '' or url == None:
                continue
            else:
                url = target_url + url
            if url not in urls:
                urls.append(url)
        else:
            if url.startswith(target_url):
                if url not in urls:
                    urls.append(url)

    secondary_urls = []

    if len(urls) < 10:
        for each_url in urls:
            reqs = requests.get(each_url)
            soup = BeautifulSoup(reqs.text, 'html.parser')
            for link in soup.find_all('a'):
                url = link.get('href')
                if url == '' or url == None:
                    continue
                elif not url.startswith('http'):
                    if url.startswith('./'):
                        url = each_url + url.lstrip('./')
                    elif url.startswith('/'):
                        url = each_url + url.lstrip('/')
                    elif "#" in url:
                        continue
                    else:
                        url = each_url + url
                    if url not in urls or not url in secondary_urls:
                        secondary_urls.append(url)
                else:
                    if url.startswith(each_url):
                        if url not in urls or not url in secondary_urls:
                            secondary_urls.append(url)

    for each_url in secondary_urls:
        if each_url not in urls:
            urls.append(each_url)
    return urls