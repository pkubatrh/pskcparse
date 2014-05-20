# Authors:
#   Petr Kubat <xkubat11@stud.fit.vutbr.cz>

"""
A module for uploading OTP information into LDAP
"""

import ldap
import getpass

def add_args(parser):
    """
    A function to add module's arguments to the argument parser
    """
    group = parser.add_argument_group('LDAP module arguments')
    group.add_argument('-H', action='store', dest='ldapuri', required=True, 
                        help='URI for connecting to a LDAP server.')
    group.add_argument('-D', action='store', dest='disname', required=True, 
                        help='Distinguished name used to bind to the server.')
    group.add_argument('-a', action='store_true', dest='aci', required=False, 
                        help='Option used to add ACI to the LDAP record.')
    group.add_argument('-B', action='store', dest='base', required=True, 
                        help='Base of the DIT where key records will be added.')
    # Only one may be set at a time
    grpmut = group.add_mutually_exclusive_group(required=True)
    grpmut.add_argument('-w', action='store', dest='passwd',
                        help='Password argument for authentication. '
                        'Cannot be used with -W')
    grpmut.add_argument('-W', action='store_true', dest='pwprompt',
                        help='Password input through a prompt. '
                        'Cannot be used with -w')
    return parser

def run(continfo, keylist, args):
    """
    A function used to run the module
    
    Arguments:
        continfo -- a dict with information about the key container
        keylist -- a list filled with keypackage objects
        args -- command line arguments
    """
    if not keylist:
        print 'No keys to upload. Shutting down.'
        exit(0)
    server = ldap.initialize(args.ldapuri)
    # Check the arguments and decide how to input the password
    if args.pwprompt:
        passwd = getpass.getpass()
    else:
        passwd = args.passwd
    server.simple_bind_s(args.disname, passwd)
    for keypack in keylist:
        # Create a new LDAP record
        record = [
            # Mandatory attributes
            ('ipatokenUniqueID', [keypack.keyinfo['Id']]),
            ('ipatokenOTPalgorithm ', [keypack.keyinfo['Algorithm']])
        ]
        if 'UserId' in keypack.keyinfo:
            record.append(('ipatokenOwner', [keypack.keyinfo['UserId']]))
        if 'Manufacturer' in keypack.devinfo:
            record.append(('ipatokenVendor', [keypack.devinfo['Manufacturer']]))
        if 'Model' in keypack.devinfo:
            record.append(('ipatokenModel', [keypack.devinfo['Model']]))
        if 'SerialNo' in keypack.keyinfo:
            record.append(('ipatokenSerial', [keypack.devinfo['SerialNo']]))
        if 'Secret' in keypack.keydata:
            record.append(('ipatokenOTPkey', [keypack.keydata['Secret']]))
        if keypack.algattr is not None and 'Length' in keypack.algattr:
            record.append(('ipatokenOTPdigits ', [keypack.algattr['Length']]))
        # Check the combination of data elements in the package
        if 'Counter' in keypack.keydata and 'TimeInterval' in keypack.keydata:
        # Counter and time
            record.append(('objectclass', ['ipaTokenmixed']))
            record.append(('ipatokenHOTPcounter', [keypack.keydata['Counter']]))
            record.append(('ipatokenTOTPtimeStep',
                            [keypack.keydata['TimeInterval']]))
        # Counter --> Hash based OTP
        elif 'Counter' in keypack.keydata:
            record.append(('objectclass', ['ipaTokenHOTP']))
            record.append(('ipatokenHOTPcounter', [keypack.keydata['Counter']]))
        # Time --> Time based OTP
        elif 'Time' in keypack.keydata:
            record.append(('objectclass', ['ipaTokenTOTP']))
            record.append(('ipatokenTOTPtimeStep',
                            [keypack.keydata['TimeInterval']]))
        # Token doesnt need neither a counter nor a time element
        else:
            record.append(('objectclass', ['ipaTokenOTP']))
        # Create and ACI if needed
        if args.aci:
            record.append(('aci', '(targetattr ="ipatokenOTPkey")(version 3.0;acl "Deny access to secret key.";deny (all)(userdn = "ldap:///all");)'))
        # Add the record to the server
        try:
            print 'Storing key ' + keypack.keyinfo['Id']
            server.add_s('ipatokenUniqueID=' + keypack.keyinfo['Id'] + ',' + args.base, record)
        except ldap.LDAPError, e:
            print 'LDAPError: ' + e.message['desc'] + '. Continuing with next key.'

