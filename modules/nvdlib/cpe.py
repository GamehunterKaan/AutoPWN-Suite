import datetime

from datetime import datetime
from .get import __get
from .classes import __convert

def searchCPE(modStartDate=False,
        modEndDate=False,
        includeDeprecated=False,
        keyword=False,
        cpeMatchString=False,
        cves=False,
        limit=False,
        key=False,
        verbose=False):

    def __buildCPECall(
        modStartDate,
        modEndDate,
        includeDeprecated,
        keyword,
        cpeMatchString,
        cves,
        limit,
        key):

        parameters = {}
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
        
        if includeDeprecated:
            parameters['includeDeprecated'] = True
        
        if keyword:
            parameters['keyword'] = keyword

        if cpeMatchString:
            parameters['cpeMatchString'] = cpeMatchString

        if cves:
            if cves == True:
                cves = 'addOns=cves'
                parameters['addOns'] = 'cves'
            else:
                raise TypeError("cves parameter can only be boolean True.")

        if limit:
            if limit > 2000 or limit < 1:
                raise ValueError('Limit parameter must be between 1 and 2000')
            parameters['resultsPerPage'] = limit

        if key:
            parameters['apiKey'] = key

        return parameters

    # Build the URL for the request
    parameters = __buildCPECall(
        modStartDate,
        modEndDate,
        includeDeprecated,
        keyword,
        cpeMatchString,
        cves,
        limit,
        key)

    # Send the GET request for the JSON and convert to dictionary
    raw = __get('cpe', parameters, limit, key, verbose)

    cpes = []
    # Generates the CVEs into objects for easy referencing and appends them to self.cves
    for eachCPE in raw['result']['cpes']:
        cpe = __convert('cpe', eachCPE)
        cpe.getvars() # Generates cpe.title and cpe.name
        cpes.append(cpe)
    return cpes