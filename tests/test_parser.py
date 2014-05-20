# Authors:
#   Petr Kubat <xkubat11@stud.fit.vutbr.cz>

"""
Tests for the parser
"""

import unittest
import sys
import xml.etree.ElementTree as ET

# Add path to parent dicertory to PYTHONPATH
sys.path.append('../')

import default
import pskcparser

class TestParser(unittest.TestCase):

    def setUp(self):
        assymetric = '../samples/assymetric.xml'
        derived = '../samples/derived.xml'
        plain = '../samples/plain.xml'
        
        tree = ET.parse(derived)
        self.deriveroot = tree.getroot()
        
        tree = ET.parse(assymetric)
        self.assymroot = tree.getroot()
        self.encelem = self.assymroot.find('pskc:KeyPackage', default.ns)
        
        tree = ET.parse(plain)
        root = tree.getroot()
        self.plainelem = root.find('pskc:KeyPackage', default.ns)
    
    def test_plain(self):
        keypack = default.KeyPack(True)
        keypack.parse(self.plainelem)
        # Test device info
        self.assertEqual(keypack.devinfo['Manufacturer'], 'Manufacturer',
                            'incorrect manufacturer')
        self.assertEqual(keypack.devinfo['SerialNo'], '987654321',
                            'incorrect serial number')
        self.assertEqual(keypack.devinfo['UserId'], 'DC=example-bank,DC=net',
                            'incorrect user ID')
        self.assertEqual(keypack.devinfo['Model'], 'one-button-HOTP-token-V1',
                            'incorrect model')
        self.assertEqual(keypack.devinfo['IssueNo'], '1',
                            'incorrect issue number')
        self.assertEqual(keypack.devinfo['DeviceBinding'], 'something',
                            'incorrect device binding')
        self.assertEqual(keypack.devinfo['StartDate'], '2009-01-22T00:25:11Z',
                            'incorrect start date')
        self.assertEqual(keypack.devinfo['ExpiryDate'], '2010-01-22T00:25:11Z',
                            'incorrect expiry date')
        # Test crypto ID
        self.assertEqual(keypack.cryptoid, 'CM_ID_001', 'incorrect crypto ID')
        # Test algorithm parameters
        self.assertEqual(keypack.algattr['Length'], '8', 'incorrect length')
        self.assertEqual(keypack.algattr['Encoding'], 'DECIMAL',
                            'incorrect encoding')
        # Test key policy
        self.assertEqual(keypack.policyinfo['Usage'], 'OTP', 
                            'incorrect key policy')
        self.assertEqual(keypack.policyinfo['StartDate'],
                            '2009-01-22T00:25:11Z', 'incorrect key policy')
        self.assertEqual(keypack.policyinfo['ExpiryDate'],
                            '2010-01-22T00:25:11Z', 'incorrect key policy')
        # Test key info
        self.assertEqual(keypack.keyinfo['Id'], '12345678',
                            'incorrect key ID')
        self.assertEqual(keypack.keyinfo['Algorithm'], 'urn:ietf:params:xml:ns'
                            ':keyprov:pskc:hotp', 'incorrect algorithm')
        self.assertEqual(keypack.keyinfo['Issuer'], 'Issuer'
                            , 'incorrect issuer')
        self.assertEqual(keypack.keyinfo['FriendlyName'], 'I-am-friendly'
                            , 'incorrect friendly name')
        self.assertEqual(keypack.keyinfo['UserId'], 'UID=jsmith,'
                                'DC=example-bank,DC=net', 'incorrect user ID')
        # Test key data
        self.assertEqual(keypack.keydata['Secret'],
                        'MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=', 'incorrect secret key')
        self.assertEqual(keypack.keydata['SecretType'], 'plain'
                            , 'incorrect secret type')
        self.assertEqual(keypack.keydata['Counter'], '0', 'incorrect counter')
        self.assertEqual(keypack.keydata['Time'], '42', 'incorrect time')
        self.assertEqual(keypack.keydata['TimeInterval'], '30'
                            , 'incorrect time interval')
        
    
    def test_encrypted(self):
        # Test container info parser for a derived key document
        continfo = parseProto.parse_keycontainer(self.deriveroot)
        # Encryption key structure
        self.assertEqual(continfo['encryption'], 'derived',
                            'incorrect encryption type')
        self.assertEqual(continfo['deralgorithm'], 'http://www.rsasecurity.com'
                         '/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2',
                         'incorrect encryption algorithm')
        self.assertEqual(continfo['salt'], 'Ej7/PEpyEpw=',
                            'incorrect salt')
        self.assertEqual(continfo['count'], '1000', 'incorrect count')
        self.assertEqual(continfo['keylength'], '16', 'incorrect key length')
        # MAC structure
        self.assertEqual(continfo['macalgorithm'], 'http://www.w3.org/2000/09/'
                         'xmldsig#hmac-sha1', 'incorrect MAC algorithm')
        self.assertEqual(continfo['encalgorithm'], 'http://www.w3.org/2001/04/'
                         'xmlenc#aes128-cbc', 'incorrect encryption algorithm')
        self.assertEqual(continfo['macvalue'], '2GTTnLwM3I4e5IO5FkufoOEiOhNj91'
                         'fhKRQBtBJYluUDsPOLTfUvoU2dStyOwYZx',
                         'incorrect MAC value')
        
        # Test the key package parser
        keypack = default.KeyPack(True)
        keypack.parse(self.encelem)
        # Test device info
        self.assertEqual(keypack.devinfo['Manufacturer'], 'TokenVendorAcme',
                            'incorrect manufacturer')
        self.assertEqual(keypack.devinfo['SerialNo'], '987654321',
                            'incorrect serial number')
        # Test algorithm parameters
        self.assertEqual(keypack.algattr['Length'], '6', 'incorrect length')
        self.assertEqual(keypack.algattr['Encoding'], 'DECIMAL',
                            'incorrect encoding')
        # Test key info
        self.assertEqual(keypack.keyinfo['Id'], 'MBK000000001',
                            'incorrect key ID')
        self.assertEqual(keypack.keyinfo['Algorithm'], 'urn:ietf:params:xml:ns'
                            ':keyprov:pskc:hotp', 'incorrect algorithm')
        self.assertEqual(keypack.keyinfo['Issuer'], 'Example-Issuer'
                            , 'incorrect issuer')
        # Test key data
        self.assertEqual(keypack.keydata['Secret'],
                            'hJ+fvpoMPMO9BYpK2rdyQYGIxiATYHTHC7e/sPLKYo5/r1v+4'
                            'xTYG3gJolCWuVMydJ7Ta0GaiBPHcWa8ctCVYmHKfSz5fdeV5n'
                            'qbZApe6dofTqhRwZK6Yx4ufevi91cjN2vBpSxYafvN3c3+xIg'
                            'k0EnTV4iVPRCR0rBwyfFrPc4='
                            , 'incorrect secret key')
        self.assertEqual(keypack.keydata['SecretType'], 'encrypted'
                            , 'incorrect secret type')
        self.assertEqual(keypack.keydata['Counter'], '0'
                            , 'incorrect counter')
    
if __name__ == '__main__':
    unittest.main()
