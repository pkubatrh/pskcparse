#!/usr/bin/python

# Authors:
#   Petr Kubat <xkubat11@stud.fit.vutbr.cz>

"""
Backend of the program. Handles CLI and communication with modules.
"""

import xml.etree.ElementTree as ET
import argparse
import importlib

from default import KeyPack as defaultkp
from default import ns
from algorithms import alglist
import modules

def add_args(parser):
    """
    Method to set backend's CLI arguments
    """
    group = parser.add_argument_group('Parser arguments')
    group.add_argument('filename', action='store', help='PSKC document file')
    group.add_argument('--filter', action='store', help='search filter')
    group.add_argument('-m','--module', dest='module', action='store',
        required=True, help='name of the module used to store parsed info')
    return parser

def parse_keycontainer(root):
    continfo = {}
    
    child = root.find('pskc:EncryptionKey', ns)
    if child is not None: 
        # Checking for various encryption types
        if (child.find('ds:KeyName', ns) is not None and   # Preshared Key
           child.find('ds:KeyName', ns).text == 'Pre-shared-key'):
            continfo['encryption'] = 'preshared'
            isencrypted = True
        elif child.find('xenc11:DerivedKey', ns) is not None:   # Derived Key
            isencrypted = True
            derived = child.find('xenc11:DerivedKey', ns)
            try:
                # Fill in the information
                continfo['encryption'] = 'derived'
                continfo['deralgorithm'] = (derived.find(
                        'xenc11:KeyDerivationMethod', ns).attrib['Algorithm'])
                # PBKDF2
                pkcs5 = derived.find('xenc11:KeyDerivationMethod/'
                                    'pkcs5:PBKDF2-params', ns)
                continfo['salt'] = pkcs5.find('Salt/Specified').text.strip()
                continfo['count'] = pkcs5.find('IterationCount').text.strip()
                continfo['keylength'] = pkcs5.find('KeyLength').text.strip()
                
            except (AttributeError, KeyError):
                exit
            
        
        elif child.find('ds:X509Data', ns) is not None:   # Assymetric key
            try:
                # Fill in the information
                continfo['encryption'] = 'assymetric'
                continfo['certificate'] = ''.join(child.find('ds:X509Data/'
                                        'ds:X509Certificate', ns).text.split())
                isencrypted = True
                
            except AttributeError, KeyError:
                exit
    
    # Checking if there is a MAC element
    child = root.find('pskc:MACMethod', ns)   # MAC Method
    if child is not None and isencrypted:
        try:
            # Fill in the information
            continfo['macalgorithm'] = child.attrib['Algorithm']
            continfo['encalgorithm'] = (child.find('pskc:MACKey/'
                            'xenc:EncryptionMethod', ns).attrib['Algorithm'])
            continfo['macvalue'] = child.find('pskc:MACKey/xenc:CipherData/'
                                            'xenc:CipherValue',ns).text.strip()
        except (AttributeError, KeyError):
            exit
    return continfo

if __name__ == '__main__':
    
    # Setup an temporary argument parser without help enabled to catch --help
    parser = argparse.ArgumentParser(add_help=False)
    # Module arguments
    parser.add_argument('-m','--module', dest='module', action='store',
        required=False, help='name of the module used to store parsed info')
    parser.add_argument('-h', '--help', action='store_true')
    # Get the arguments needed to import the plugin
    args, unknown = parser.parse_known_args()
    # Only --help is set
    if args.help and args.module is None:
        # Make a new parser with help enabled
        parser = argparse.ArgumentParser(add_help=True)
        # Add only backend's arguments, print help and exit
        parser = add_args(parser)
        parser.print_help()
        parser.exit()
    # neither --help nor --module is set
    elif args.module is None:
        # Make a new parser
        parser = argparse.ArgumentParser()
        # Add only backend's arguments, exit with error
        parser = add_args(parser)
        parser.error('too few arguments')
    
    # Else continue and let the new parser take care of --help
    # Import the chosen plugin from the modules package
    try:
        mod = importlib.import_module('.' + args.module, 'modules')
    except ImportError, e:
        print 'Import error: ', str(e)
        exit(1)
    
    # Setup a new parser with help enabled
    parser = argparse.ArgumentParser()
    # Module arguments
    parser = add_args(parser)
    # Add the plugin's arguments
    parser = mod.add_args(parser)
    # Parse the arguments one last time
    args = parser.parse_args()
    
    # A variable to check if the container is encrypted
    isencrypted = False
    
    # Parse the XML and try to find the EncryptionKey element
    tree = ET.parse(args.filename)
    root = tree.getroot()
    
    # Preparse the document and get info about the container
    continfo = parse_keycontainer(root)
    # Remove parsed elements from xml tree if any
    child = root.find('pskc:EncryptionKey', ns)   # Encryption key
    if child is not None:
        root.remove(child)
    child = root.find('pskc:MACMethod', ns)   # MAC Method
    if child is not None:
        root.remove(child)
    
    keylist = []
    # Iterate over all key packages
    for child in root:
        # Get the algorithm id
        algorithm = child.find('pskc:Key', ns).attrib['Algorithm']
        # If the key uses an implemented algorithm
        if algorithm in alglist:
            keypack = alglist[algorithm](isencrypted)
        else:
            # Algorithm unknown, try using the default parser
            keypack = defaultkp(isencrypted)
        errstate = keypack.parse(child)
        if errstate == 1:
            continue
        if args.filter is not None:
            # If the filter is a substring in the key identificator
            if keypack.keyinfo['Id'].find(args.filter) != -1:
                keylist.append(keypack)
            # If the filter is a substring in the key's user identificator
            elif ('UserId' in keypack.keyinfo and
                    keypack.keyinfo['UserId'].find(args.filter) != -1):
                keylist.append(keypack)
        else:
            keylist.append(keypack)
    # After parsing every key, run the chosen module
    mod.run(continfo, keylist, args)
    exit(0)
