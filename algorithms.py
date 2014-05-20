# Authors:
#   Petr Kubat <xkubat11@stud.fit.vutbr.cz>

"""
Contains the implementation of extensions for the default PSKC parser
"""

from default import KeyPack
from default import ns
from default import PskcError

class Yubikey(KeyPack):
    """
    An extension for the yubikey token
    """
    def __init__(self, encrypt):
        """
        Initialization method for the object
        
        encrypt -- boolean to see if the package uses encryption
        """
        KeyPack.__init__(self, encrypt)
        # Yubikey requires AlgorithmParameters
        self.algparamreq = True
    
    def parse(self, element):
        """
        Extends the default parser
        """
        KeyPack.parse(self, element)
        try:
            if self.devinfo['Manufacturer'] != 'oath.UB':
                raise PskcError
            if self.devinfo['StartDate'] is None:
                raise PskcError
            # cryptoid marks ports on the Yubikey token - 1 or 2
            if self.cryptoid != '1' and self.cryptoid != '2':
                raise PskcError
            if (self.algattr['Encoding'] != 'ALPHANUMERIC' or
                'Length' not in self.algattr):
                raise PskcError
            return 0
        except (PskcError, KeyError):
            print ('Error! Key ' + self.keyinfo['Id'] + ' is not a valid'
            ' Yubico key.')
            return 1

class Hotp(KeyPack):
    """
    An extension for the oath HOTP token
    """
    def __init__(self, encrypt):
        """
        Initialization method for the object
        
        encrypt -- boolean to see if the package uses encryption
        """
        KeyPack.__init__(self, encrypt)
        # HOTP requires AlgorithmParameters
        self.algparamreq = True
    
    def parse(self, element):
        """
        Extends the default parser
        """
        KeyPack.parse(self, element)
        try:
            # Encoding and Lenght both need to be set
            if 'Encoding' not in self.algattr or 'Length' not in self.algattr:
                raise PskcError
            # Encoding needs to be DECIMAL
            if self.algattr['Encoding'] != 'DECIMAL':
                raise PskcError
            # Counter needs to be present
            if 'Counter' not in self.keydata:
                raise PskcError
            return 0
        except PskcError:
            print ('Error! Key ' + self.keyinfo['Id'] + ' is not a valid '
                    'HOTP key.')
            return 1
class Totp(KeyPack):
    """
    An extension for the oath TOTP token
    """
    def __init__(self, encrypt):
        """
        Initialization method for the object
        
        encrypt -- boolean to see if the package uses encryption
        """
        KeyPack.__init__(self, encrypt)
        # TOTP requires AlgorithmParameters
        self.algparamreq = True
        # TOTP requires Key policy (Usage)
        self.keypolicyreq = True
    
    def parse(self, element):
        """
        Extends the default parser
        """
        KeyPack.parse(self, element)
        try:
            # Encoding and Lenght both need to be set
            if 'Encoding' not in self.algattr or 'Length' not in self.algattr:
                raise PskcError
            # Time and TimeInterval elements need to be present in the key data
            if 'Time' not in self.keydata or 'TimeInterval' not in self.keydata:
                raise PskcError
            # Encoding needs to be DECIMAL
            if self.algattr['Encoding'] != 'DECIMAL':
                raise PskcError
            return 0
        except PskcError:
            print ('Error! Key ' + self.keyinfo['Id'] + ' is not a valid '
                    'TOTP key.')
            return 1

# ! Following extensions might be outdated !

class SecurIdAes(KeyPack):
    """
    An extension for RSA's SecurID token using AES
    """
    def __init__(self, encrypt):
        """
        Initialization method for the object
        
        encrypt -- boolean to see if the package uses encryption
        """
        KeyPack.__init__(self, encrypt)
        # SecurID requires AlgorithmParameters
        self.algparamreq = True
        # SecurID requires Key policy
        self.keypolicyreq = True
        
    def parse(self, element):
        """
        Extends the default parser
        """
        KeyPack.parse(self, element)
        try:
            # Start date and expiry date both need to be set
            if ('StartDate' not in self.policyinfo or
                    'ExpiryDate' not in self.policyinfo):
                raise PskcError
            # Encoding needs to be DECIMAL
            if self.algattr['Encoding'] != 'DECIMAL':
                raise PskcError
            # Length needs to be at least 6
            if int(self.algattr['Length']) < 6:
                raise PskcError
            return 0
        except PskcError:
            print ('Error! Key ' + self.keyinfo['Id'] + ' is not a valid '
                    'TOTP key.')
            return 1

class SecurIdCntr(KeyPack):
    """
    An extension for RSA's SecurID token using AES with a counter
    """
    def __init__(self, encrypt):
        """
        Initialization method for the object
        
        encrypt -- boolean to see if the package uses encryption
        """
        KeyPack.__init__(self, encrypt)
        # SecurID requires AlgorithmParameters
        self.algparamreq = True
        # SecurID requires Key policy
        self.keypolicyreq = True
    
    def parse(self, element):
        """
        Extends the default parser
        """
        KeyPack.parse(self, element)
        try:
            # Start date and expiry date both need to be set
            if ('StartDate' not in self.policyinfo or
                    'ExpiryDate' not in self.policyinfo):
                raise PskcError
            # Encoding needs to be DECIMAL
            if self.algattr['Encoding'] != 'DECIMAL':
                raise PskcError
            # Length needs to be at least 6
            if int(self.algattr['Length']) < 6:
                raise PskcError
            # Counter needs to be present
            if 'Counter' not in self.keydata:
                raise PskcError
            return 0
        except PskcError:
            print ('Error! Key ' + self.keyinfo['Id'] + ' is not a valid '
                    'TOTP key.')
            return 1

class SecurIdAlgor(KeyPack):
    """
    An extension for RSA's SecurID token using ALGOR
    """
    def __init__(self, encrypt):
        """
        Initialization method for the object
        
        encrypt -- boolean to see if the package uses encryption
        """
        # SecurID requires AlgorithmParameters
        self.algparamreq = True
        # SecurID requires Key policy
        self.keypolicyreq = True
        KeyPack.__init__(self, encrypt)
    
    def parse(self, element):
        """
        Extends the default parser
        """
        KeyPack.parse(self, element)
        try:
            # Start date and expiry date both need to be set
            if ('StartDate' not in self.policyinfo or
                    'ExpiryDate' not in self.policyinfo):
                raise PskcError
            # Encoding needs to be DECIMAL
            if self.algattr['Encoding'] != 'DECIMAL':
                raise PskcError
            # Length needs to be at least 6
            if int(self.algattr['Length']) < 6:
                raise PskcError
            return 0
        except PskcError:
            print ('Error! Key ' + self.keyinfo['Id'] + ' is not a valid '
                    'TOTP key.')
            return 1


# A dict for calling extensions in the main program
alglist = {'http://www.yubico.com/#yubikey-aes' : Yubikey,
           'urn:ietf:params:xml:ns:keyprov:pskc:hotp' : Hotp,
           'urn:ietf:params:xml:ns:keyprov:pskc#totp' : Totp,
           
           # ! Following algorithm URIs are probably outdated !
           
           'http://www.rsasecurity.com/rsalabs/otps/schemas/2005/09/'
                'otps-wst#SecurID-AES' : SecurIdAes,
           'http://www.rsa.com/names/2008/04/algorithms/SecurID/'
                'SecurID-AES128-Counter' : SecurIdCntr,
           'http://www.rsasecurity.com/rsalabs/otps/schemas/2005/09/'
                'otps-wst#SecurID-ALGOR' : SecurIdAlgor
           }
