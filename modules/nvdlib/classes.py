import json

class CPE:
    """JSON dump class for CPEs

    :var name: CPE URI name
    :vartype name: str

    :var title: The first title result of the CPE.
    :vartype title: str

    :var deprecated: Indicates whether CPE has been deprecated
    :vartype deprecated: bool

    :var cpe23Uri: The CPE name
    :vartype cpe23Uri: str

    :var lastModifiedDate: CPE modification date
    :vartype lastModifiedDate: 

    :var titles: Human-readable CPE titles
    :vartype titles: dict

    :var refs: Reference links.
    :vartype refs: dict

    :var deprecatedBy: If deprecated=true, one or more CPE that replace this one
    :vartype deprecatedby: list

    :var vulnerabilities: Optional vulnerabilities associated with this CPE. Must use 'cves = true' argument in searchCPE.
    :vartype vulnerabilities: list
    """

    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):
        self.title = self.titles[0].title
        self.name = self.cpe23Uri


class CVE:
    """JSON dump class for CVEs

    :var cve: CVE ID, description, reference links, CWE.
    :vartype cve: dict

    :var configurations: CPE applicability statements and optional CPE names.
    :vartype  configurations: dict

    :var impact: CVSS severity scores
    :vartype impact: dict

    :var publishedDate: CVE publication date
    :vartype publishedDate: ISO 8601 date/time format including time zone.

    :var lastModifiedDate: CVE modified date
    :vartype lastModifiedDate: ISO 8601 date/time format including time zone.

    :var id: CVE ID
    :vartype id: str

    :var cwe: Common Weakness Enumeration Specification (CWE)
    :vartype cwe: str

    :var url: Link to additional details on nvd.nist.gov for that CVE.
    :vartype url: str

    :var v3score: List that contains V3 or V2 CVSS score (float 1 - 10) as index 0 and the version that score was taken from as index 1.
    :vartype v3score: list

    :var v2vector: Version two of the CVSS score represented as a vector string, a compressed textual representation of the values used to derive the score.
    :vartype v2vector: str

    :var v3vector: Version three of the CVSS score represented as a vector string.
    :vartype v3vector: str

    :var v2severity: LOW, MEDIUM, HIGH (Critical is only available for v3).
    :vartype v2severity: str

    :var v3severity: LOW, MEDIUM, HIGH, CRITICAL.
    :vartype v3severity: str

    :var v2exploitability: Reflects the ease and technical means by which the vulnerability can be exploited.
    :vartype v2exploitability: float 

    :var v3exploitability: Reflects the ease and technical means by which the vulnerability can be exploited.
    :vartype v3exploitability: float 

    :var v2impactScore: Reflects the direct consequence of a successful exploit.
    :vartype v2impactScore: float

    :var v3impactScore: Reflects the direct consequence of a successful exploit.
    :vartype v3impactScore: float

    :var score: Contains the v3 CVSS score (v2 if v3 isn't available) [score, severity, version]. Where score is an int, severity is a string('LOW','MEDIUM','HIGH','CRITICAL'), and version is a string (V3 or V2).
    :vartype score: list
    """

    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):
        
        self.id = self.cve.CVE_data_meta.ID 
        """ ID of the CVE """
        self.cwe = self.cve.problemtype.problemtype_data
        self.url = 'https://nvd.nist.gov/vuln/detail/' + self.id

        if hasattr(self.impact, 'baseMetricV3'):
            self.v3score = self.impact.baseMetricV3.cvssV3.baseScore
            self.v3vector = self.impact.baseMetricV3.cvssV3.vectorString
            self.v3severity = self.impact.baseMetricV3.cvssV3.baseSeverity
            self.v3exploitability = self.impact.baseMetricV3.exploitabilityScore
            self.v3impactScore = self.impact.baseMetricV3.impactScore

        if hasattr(self.impact, 'baseMetricV2'):
            self.v2score = self.impact.baseMetricV2.cvssV2.baseScore
            self.v2vector = self.impact.baseMetricV2.cvssV2.vectorString
            self.v2severity = self.impact.baseMetricV2.severity
            self.v2exploitability = self.impact.baseMetricV2.exploitabilityScore
            self.v2impactScore = self.impact.baseMetricV2.impactScore
        
        # Prefer the base score version to V3, if it isn't available use V2.
        # If no score is present, then set it to None.
        if hasattr(self.impact, 'baseMetricV3'):
            self.score = ['V3', self.impact.baseMetricV3.cvssV3.baseScore, self.impact.baseMetricV3.cvssV3.baseSeverity]
        elif hasattr(self.impact, 'baseMetricV2'):
            self.score = ['V2', self.impact.baseMetricV2.cvssV2.baseScore, self.impact.baseMetricV2.severity]
        else:
            self.score = [None, None, None]

def __convert(product, CVEID):
    """Convert the JSON response to a referenceable object."""
    if product == 'cve':
        vuln = json.loads(json.dumps(CVEID), object_hook= CVE)
        vuln.getvars()
        return vuln
    else:
        cpeEntry = json.loads(json.dumps(CVEID), object_hook= CPE)
        return cpeEntry 