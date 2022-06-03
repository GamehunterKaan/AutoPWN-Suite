import requests
import time

from json.decoder import JSONDecodeError


def __get(product, parameters, limit, key, verbose):
    """Calculate required pages for multiple requests, send the GET request with the search criteria, return list of CVEs or CPEs objects."""

    # NIST 6 second rate limit recommendation on requests without API key - https://nvd.nist.gov/developers
    # Get a key, its easy.
    if key:
        delay = 0.6
    else:
        delay = 6 

    # Get the default 20 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/1.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/1.0?'
    else:
        raise ValueError('Unknown Product')
    
    if verbose:
        print('Filter:\n' + link)
        print(parameters)

    raw = requests.get(link, params=parameters)
    

    try: # Try to convert the request to JSON. If it is not JSON, then raise an exception.
        raw = raw.json() 
        if 'message' in raw:
            raise LookupError(raw['message'])
    except JSONDecodeError:
        raise LookupError("Invalid search criteria syntax: " + str(raw) +
                          "\nPlease check your search criteria syntax and try again."
                          "\nAttempted search criteria: " + str(parameters))

    time.sleep(delay) 
    totalResults = raw['totalResults']

    # If a limit is in the search criteria or the total number of results are less than or equal to the default 20 that were just requested, return and don't request anymore.
    if limit or totalResults <= 20:
        return raw

    # If the total results is less than the API limit (Should be 5k but tests shows me 2k), just grab all the results at once.
    elif totalResults > 20 and totalResults < 2000:
        parameters['resultsPerPage'] = str(totalResults)
        raw = requests.get(link, params=parameters).json()
        return raw

    # If the results is more than the API limit, figure out how many pages there are and calculate the number of requests.
    # Send a request starting at startIndex = 0, then get the next page and ask for 2000 more results at the 2000th index result until all results have been grabbed.
    # Add each ['CVE_Items'] list from each page to the end of the first request. Effectively creates one data point.
    elif totalResults > 2000:
        pages = (totalResults // 2000) + 1
        startIndex = 0
        rawTemp = []
        if product == 'cve':
            for eachPage in range(pages):
                parameters['resultsPerPage'] = '2000'
                parameters['startIndex'] = str(startIndex)
                time.sleep(delay)
                getData = requests.get(link, params=parameters).json()['result']['CVE_Items']
                for eachCVE in getData:
                    rawTemp.append(eachCVE.copy())
                startIndex += 2000
            raw['result']['CVE_Items'] = rawTemp
            return raw
        elif 'cpe':
            for eachPage in range(pages):
                parameters['resultsPerPage'] = '2000'
                parameters['startIndex'] = str(startIndex)
                time.sleep(delay)
                getData = requests.get(link, params=parameters).json()['result']['cpes']
                for eachCPE in getData:
                    rawTemp.append(eachCPE.copy())
                startIndex += 2000
            raw['result']['cpes'] = rawTemp
            return raw