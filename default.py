# Authors:
#   Petr Kubat <xkubat11@stud.fit.vutbr.cz>

"""
Implements the parsing of an unextended PSKC document
"""

# A variable for storing namespaces used by the PSKC RFC
ns = {'pskc' : 'urn:ietf:params:xml:ns:keyprov:pskc',
        'ds' :'http://www.w3.org/2000/09/xmldsig#' ,
        'xenc' : 'http://www.w3.org/2001/04/xmlenc#', 
        'xenc11' : 'http://www.w3.org/2009/xmlenc11#',
        'pkcs5' : 'http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#'
        }

class PskcError(Exception):
    """
    An exception to denote an unvalid input document
    """
    pass

class KeyPack:
    """
    A class for defining key packages
    """
    def __init__(self, encrypt):
        """
        Initialization method for the object
        
        Arguments:
            encrypt -- boolean to see if the package uses encryption
        """
        self._otppolicy = False
        
        self.algparamreq = False
        self.keypolicyreq = False
        self.isencrypted = encrypt
        self.pinattr = None
        self.algattr = None
        self.cryptoid = None
        self.extelement = None
        self.extxml = None
        # Dicts to store info and data
        self.devinfo = {}
        self.keyinfo = {}
        self.keydata = {}
        self.policyinfo = {}
    
    def print_keys(self):
        """
        Prints information about the package
        """
        print ''
        print '### Key Package ###'
        # Key Information
        for key in self.keyinfo:
            print key + ': ' + self.keyinfo[key]
        
        # Key Data
        for key in self.keydata:
            print key + ': ' + self.keydata[key]
        
        if self.algattr is not None:
            print '# Response format #'
            for key in self.algattr:
                print key, self.algattr[key]
        
        if self.pinattr is not None:
            print '# Pin Policy #'
            for key in self.pinattr:
                print key, self.pinattr[key]
        
        if self.policyinfo is not None:
            print '# Key Policy #'
            for key in self.policyinfo:
                print key, self.policyinfo[key]
        
        print '# Device Info: #'
        # Device Info
        for key in self.devinfo:
            print key + ': ' + self.devinfo[key]
        print 'Crypto Module ID: ' + str(self.cryptoid)
    
    def parse_KeyPolicy(self, element):
        """
        Method for parsing the key's Policy element
        """
        self.policyinfo = {}
        
        # See if the key can be used for OTP
        childList = element.findall('pskc:KeyUsage', ns)
        for child in childList:
            if child.text == 'OTP':
                self._otppolicy = True
                self.policyinfo['Usage'] = 'OTP'
        if not self._otppolicy:
            raise PskcError("Parser Error: This key cannot be used for OTP.")
        
        # Start date and expiry dat of the key
        child = element.find('pskc:StartDate', ns)
        if child is not None:
            self.policyinfo['StartDate'] = child.text.strip()
        
        child = element.find('pskc:ExpiryDate', ns)
        if child is not None:
            self.policyinfo['ExpiryDate'] = child.text.strip()
        
        # Policy for a PIN
        child = element.find('pskc:PINPolicy', ns)
        if child is not None:
            self.pinattr = child.attrib

    def parse_AlgParam(self, element):
        """
        Method for parsing the key's AlgorithmParameters element
        """
        
        child = element.find('pskc:ResponseFormat', ns)
        if child is not None:
            self.algattr = child.attrib   # Algorithm Attributes
    
    def parse_DevInfo(self, element):
        """
        Method for parsing the DeviceInfo element
        """
        
        # Lookup required information and parse it
        child = element.find('pskc:Manufacturer', ns)
        if child is not None:
            self.devinfo['Manufacturer'] = child.text.strip()
        child = element.find('pskc:SerialNo', ns)
        if child is not None:
            self.devinfo['SerialNo'] = child.text.strip()
        child = element.find('pskc:Model', ns)
        if child is not None:
            self.devinfo['Model'] = child.text.strip()
        child = element.find('pskc:IssueNo', ns)
        if child is not None:
            self.devinfo['IssueNo'] = child.text.strip()
        child = element.find('pskc:DeviceBinding', ns)
        if child is not None:
            self.devinfo['DeviceBinding'] = child.text.strip()
        child = element.find('pskc:StartDate', ns)
        if child is not None:
            self.devinfo['StartDate'] = child.text.strip()
        child = element.find('pskc:ExpiryDate', ns)
        if child is not None:
            self.devinfo['ExpiryDate'] = child.text.strip()
        child = element.find('pskc:UserId', ns)
        if child is not None:
            self.devinfo['UserId'] = child.text.strip()
    
    def parse_Key(self, element):
        """
        Method for parsing the Key element
        """
        
        # Parse key ID and algorithm
        try:
            self.keyinfo['Id'] = element.attrib['Id']
            self.keyinfo['Algorithm'] = element.attrib['Algorithm']
        except KeyError:
            raise PskcError('Parser Error: Key ID or algorithm not found.')
        
        # See if the algorithm needs some parameters
        child = element.find('pskc:AlgorithmParameters', ns)
        if child is None:
            if self.algparamreq:
                raise PskcError('Parser Error: Algorithm parameters not found.')
        else:
            self.parse_AlgParam(child)
            
        # See if the key has an OTP policy
        child = element.find('pskc:Policy', ns)
        if child is None:
            if self.keypolicyreq:
                print 'Error. Key policy not found.'
        else:
            self.parse_KeyPolicy(child)
        
        # Lookup some additional info and parse it
        child = element.find('pskc:FriendlyName', ns)   # Friendly Name
        if child is not None:
            self.keyinfo['FriendlyName'] = child.text.strip()
        child = element.find('pskc:Issuer', ns)   # Issuer
        if child is not None:
             self.keyinfo['Issuer'] = child.text.strip()
        child = element.find('pskc:UserId', ns)   # UserId
        if child is not None:
             self.keyinfo['UserId'] = child.text.strip()
        child = element.find('pskc:KeyProfileId', ns)   # KeyProfileId
        if child is not None:
             self.keyinfo['KeyProfileId'] = child.text.strip()
        child = element.find('pskc:KeyReference', ns)   # KeyReference
        if child is not None:
             self.keyinfo['KeyReference'] = child.text.strip()
        child = element.find('pskc:Extensions', ns)   # Extensions
        if child is not None:
             self.extelement = child
        
        # Parsing the key data
        data = element.find('pskc:Data', ns)
        # Try to find the actual key structure
        secret = data.find('pskc:Secret', ns)
        if secret is not None:
            # Checking for various key types
            if secret.find('pskc:PlainValue', ns) is not None:   # Plain Key
                self.keydata['Secret'] = (secret.find('pskc:PlainValue', ns)
                .text.strip())
                self.keydata['SecretType'] = 'plain'
            elif (secret.find('pskc:EncryptedValue', ns) is not None and
                  self.isencrypted):   # Encrypted Key Structure
                child = secret.find('pskc:EncryptedValue', ns)
                try:    
                    (child.find('xenc:EncryptionMethod', ns)
                           .attrib['Algorithm'])   # Encryption Algorithm
                    # Encrypted Key
                    self.keydata['Secret'] = ''.join((child.find('xenc:'
                    'CipherData/xenc:CipherValue', ns).text.split()))
                    self.keydata['SecretType'] = 'encrypted'
                    self.keydata['MAC'] = (secret.find('pskc:ValueMAC', ns)
                    .text.strip())    # MAC
                except (AttributeError, KeyError):
                    raise PskcError('Parse Error: Encrypted key format not valid')
                    
        # Parsing the rest of the data structure
        if data.find('pskc:Counter', ns) is not None:   # Counter
            self.keydata['Counter'] = data.find('pskc:Counter/'
            'pskc:PlainValue', ns).text.strip()
        if data.find('pskc:Time', ns) is not None:   # Time
            self.keydata['Time'] = data.find('pskc:Time/'
            'pskc:PlainValue', ns).text.strip()
        if data.find('pskc:TimeInterval', ns) is not None:   # TimeInterval
            self.keydata['TimeInterval'] = data.find('pskc:TimeInterval/'
            'pskc:PlainValue', ns).text.strip()
        # possibly timedrift?
    
    def parse(self, element):
        """
        Method for parsing the key package
        """
        
        try:
            # Try to find info about the device and parse it
            child = element.find('pskc:DeviceInfo', ns)
            if child is not None: 
                self.parse_DevInfo(child)
            
            # Try to find info about the crypto module and parse it
            child = element.find('pskc:CryptoModuleInfo', ns)
            if child is not None: 
                try:
                    self.cryptoid = child.find('pskc:Id', ns).text.strip()
                except AttributeError:
                    raise PskcError('Parser Error: Missing Crypto Module ID!')
            
            # Parse the key
            child = element.find('pskc:Key', ns)
            # The package doesn't need to have an actual key inside
            if child is not None: 
                self.parse_Key(child)
            return 0
        except PskcError, e:
            print str(e)
            return 1
    
