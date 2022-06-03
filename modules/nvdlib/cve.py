import requests
import datetime
import time

from json.decoder import JSONDecodeError
from datetime import datetime
from .classes import __convert
from .get import __get

def getCVE(CVEID, cpe_dict=False, key=False, verbose=False):
    """Build and send GET request for a single CVE then return object containing CVE attributes.

    :param CVEID: String of the CVE ID of the vulnerability to retrieve more details.
    :type CVEID: str

    :param cpe_dict: Set this value to true to control whether matching CPE names from the Official Dictionary are included in the response.
    :type cpe_dict: Bool True

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool

    """
    def __get(CVEID, cpe_dict, key, verbose):
        searchCriteria = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + CVEID + '?'
        parameters = {'addOns' : None}

        if cpe_dict == True:
            parameters['addOns'] = 'dictionaryCpes'
        elif type(cpe_dict) != bool:
            raise TypeError("cpe_dict parameter must be boolean True or False.")
        
        if key: # add the api key to the request
            if type(key) == str:
                parameters['apiKey'] = key
            else:
                raise TypeError("key parameter must be string.")
        
        if verbose:
            print('Filter:\n' + searchCriteria)
            print(parameters)
        
        raw = requests.get(searchCriteria, parameters)

        try:
            raw = raw.json()
            if 'message' in raw: # If no results were found raise error with the message provided from the API
                raise LookupError(raw['message'])

        except JSONDecodeError:
            raise LookupError("Invalid CVE: " + str(raw) +
                            "\nPlease check your CVE ID syntax and try again."
                            "\nAttempted CVE ID: " + CVEID)

        # NIST 6 second rate limit recommendation on requests without API key - https://nvd.nist.gov/developers
        # Get a key, its easy.
        if key:
            delay = 0.6
        else:
            delay = 6
        time.sleep(delay)

        return raw

    raw = __get(CVEID, cpe_dict, key, verbose)    
    return __convert('cve', raw['result']['CVE_Items'][0])



def searchCVE(
            keyword=False, 
            pubStartDate=False, 
            pubEndDate=False, 
            modStartDate=False, 
            modEndDate=False, 
            includeMatchStringChange=False, 
            exactMatch=False,
            cvssV2Severity=False,
            cvssV3Severity=False,
            cvssV2Metrics=False,
            cvssV3Metrics=False,
            cpeMatchString=False,
            cpeName=False,
            cpe_dict=False,
            cweId=False,
            limit=False,
            key=False,
            verbose=False):
    """Build and send GET request then return list of objects containing a collection of CVEs.

    :param pubStartDate: The pubStartDate and pubEndDate parameters specify the set of CVE that were added to NVD (published) during the period. 
    
        Maximum 120 day range. A start and end date is required. All times are in UTC 00:00.

        A datetime object or string can be passed as a date. NVDLib will automatically parse the datetime object into the correct format.
    
        String Example: '2020-06-28 00:00'
    :type pubStartDate: str/datetime obj

    
    :param pubEndDate: Publish end date. Can be used to get all vulnerabilities published up to a specific date and time. All times are in UTC 00:00. A start and end date is required.
    :type pubEndDate: str/datetime obj

    :param modStartDate: The modStartDate and modEndDate parameters specify CVE that were subsequently modified. All times are in UTC 00:00. A start and end date is required.
    :type modStartDate: str/datetime obj

    :param modEndDate: Modifified end date. Can be used to get all vulnerabilities modfied up to a specific date and time. All times are in UTC 00:00. A start and end date is required.
    :type modEndDate: str/datetime obj

    :param includeMatchStringChange: Retrieve vulnerabilities where CPE names changed during the time period. This returns 
        vulnerabilities where either the vulnerabilities or the associated product names were modified.
    :type includeMatchStringChange: bool True

    :param keyword: Word or phrase to search the vulnerability description or reference links.
    :type keyword: str

    :param exactMatch: If the keyword is a phrase, i.e., contains more than one term, then the isExactMatch parameter may be
        used to influence the response. Use exactMatch to retrieve records matching the exact phrase.
        Otherwise, the results contain any record having any of the terms.
    :type exactMatch: bool True

    :param cvssV2Severity: Find vulnerabilities having a 'LOW', 'MEDIUM', or 'HIGH' version 2 score.
    :type cvssV2Severity: str

    :param cvssV3Severity: -- Find vulnerabilities having a 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL' version 3 score.
    :type cvssV3Severity: str

    :param cvssV2Metrics / cvssV3Metrics: -- If your application supports CVSS vector strings, use the cvssV2Metric or cvssV3Metrics parameter to
        find vulnerabilities having those score metrics. Partial vector strings are supported.
    :type cvssV2Metrics: str

    :param cpeMatchString: -- Use cpeMatchString when you want a broader search against the applicability statements attached to the Vulnerabilities 
        (e.x. find all vulnerabilities attached to a specific product).
    :type cpeMatchString: str

    :param cpeName: -- Use cpeName when you know what CPE you want to compare against the applicability statements 
        attached to the vulnerability (i.e. find the vulnerabilities attached to that CPE). 
    :type cpeName: str

    :param cpe_dict: -- Set this value to true to control whether matching CPE from the Official Dictionary for each CVE are included in the response.

        **Warning:** If your search contains many results, the response will be very large as it will contain every CPE that a vulnerability has, thus resulting in delays.
    :type cpe_dict: bool True

    :param limit: -- Custom argument to limit the number of results of the search. Allowed any number between 1 and 2000.
    :type limit: int
    
    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool    
    """
    def __buildCVECall(
            keyword, 
            pubStartDate, 
            pubEndDate, 
            modStartDate, 
            modEndDate, 
            includeMatchStringChange, 
            exactMatch,
            cvssV2Severity,
            cvssV3Severity,
            cvssV2Metrics,
            cvssV3Metrics,
            cpeMatchString,
            cpeName,
            cpe_dict,
            cweId,
            limit,
            key):
        
        parameters = {}
        
        if keyword:
            parameters['keyword'] = keyword

        if pubStartDate:
            if isinstance(pubStartDate, datetime):
                date = pubStartDate.replace(microsecond = 0).isoformat() + ':000 UTC-00:00'
            elif isinstance(pubStartDate, str):
                date = str(datetime.strptime(pubStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + pubEndDate)
            parameters['pubStartDate'] = date
        
        if pubEndDate:
            if isinstance(pubEndDate, datetime):
                date = pubEndDate.replace(microsecond = 0).isoformat() + ':000 UTC-00:00'
            elif isinstance(pubEndDate, str):
                date = str(datetime.strptime(pubEndDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + pubEndDate)
            parameters['pubEndDate'] = date
        
        if modStartDate:
            if isinstance(modStartDate, datetime):
                date = modStartDate.replace(microsecond = 0).isoformat() + ':000 UTC-00:00'
            elif isinstance(modStartDate, str):
                date = str(datetime.strptime(modStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + modStartDate)
            parameters['modStartDate'] = date

        if modEndDate:
            if isinstance(modEndDate, datetime):
                date = modEndDate.replace(microsecond = 0).isoformat() + ':000 UTC-00:00'
            elif isinstance(modEndDate, str):
                date = str(datetime.strptime(modEndDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + modEndDate)
            parameters['modEndDate'] = date

        if includeMatchStringChange:
            if includeMatchStringChange == True:
                parameters['includeMatchStringChange'] = True
            else:
                raise TypeError("includeMatchStringChange parameter can only be boolean True.")

        if exactMatch:
            if exactMatch == True:
                parameters['exactMatch'] = True
            else:
                raise TypeError("exactMatch parameter can only be boolean True.")

        if cvssV2Severity:
            cvssV2Severity = cvssV2Severity.upper()
            if cvssV2Severity in ['LOW', 'MEDIUM', 'HIGH']:
                parameters['cvssV2Severity'] = cvssV2Severity
            else:
                raise ValueError("cvssV2Severity parameter can only be assigned LOW, MEDIUM, or HIGH value.")

        if cvssV3Severity:
            cvssV3Severity = cvssV3Severity.upper()
            if cvssV3Severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                parameters['cvssV3Severity'] = cvssV3Severity
            else:
                raise ValueError("cvssV3Severity parameter can only be assigned LOW, MEDIUM, HIGH, or CRITICAL value.")

        if cvssV2Metrics:
            parameters['cvssV2Metrics'] = cvssV2Metrics
        
        if cvssV3Metrics:
            parameters['cvssV3Metrics'] = cvssV3Metrics

        if cpeMatchString:
            parameters['cpeMatchString'] = cpeMatchString
        
        if cpeName:
            parameters['cpeName'] = cpeName

        if cpe_dict:
            if cpe_dict == True:
                parameters['addOns'] = 'dictionaryCpes'
            else:
                raise TypeError("cpe_dict parameter can only be boolean True.")

        if cweId:
            parameters['cweId'] = cweId

        if limit:
            if limit > 2000 or limit < 1:
                raise ValueError('Limit parameter must be between 1 and 2000')
            parameters['resultsPerPage'] = str(limit)
        
        if key:
            parameters['apiKey'] = key

        return parameters

    parameters = __buildCVECall(keyword, 
            pubStartDate, 
            pubEndDate, 
            modStartDate, 
            modEndDate, 
            includeMatchStringChange, 
            exactMatch,
            cvssV2Severity,
            cvssV3Severity,
            cvssV2Metrics,
            cvssV3Metrics,
            cpeMatchString,
            cpeName,
            cpe_dict,
            cweId,
            limit,
            key)

    # raw is the raw dictionary response.
    raw = __get('cve', parameters, limit, key, verbose)
    cves = []
    # Generates the CVEs into objects for easy access and appends them to self.cves
    for eachCVE in raw['result']['CVE_Items']:
        cves.append(__convert('cve', eachCVE))
    return cves
