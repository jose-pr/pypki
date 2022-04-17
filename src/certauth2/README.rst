

Fork of https://github.com/ikreymer/certauth with a lot of changes. 

Use cryptography.

Ability to use password with the ca or host certificates

Ability to select encoding to use for backend

Ability to cache credentials in the desired format



Certificate Authority Certificate Maker Tools
=============================================

This package provides a small library, built on top of ``cryptography``, which allows for creating a custom certificate authority certificate, and genereating on-demand dynamic host certs.

It is most useful for use with a man-in-the-middle HTTPS proxy, for example, for recording or replaying web content.

Trusting the CA created by this tool should be used with caution in a controlled setting to avoid security risks.


CertificateAuthority API
============================

The ``CertificateAuthority`` class provides an interface to manage a root CA and generate dynamic host certificates suitable
for use with the native Python ``ssl`` library as well as pyOpenSSL ``SSL`` module and also with the ``cryptography`` module.

The class provides several options for storing the root CA and generated host CAs.


File-based Certificate Cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   # Create a store that returns paths to the files it created, also choose an encoding for saving the files
   ## DER return 3 paths (cert, key, chain) , the chain is a tar archive with a der encoded file per cert in chain
   ## PEM and PKCS12 return 1 path
   certStore = ondiskPathStore("/tmp/certs", encoding=Encoding.PEM)

   # First argument is the certificate to use the format for a file based certificate is:
   ## A tuple with 3 elements: <filepath:str>, <cert_name:str|None>, <password:str|None> 
   ## Or a single string: <filepath:str>
   ca = CertificateAuthority(('my-ca.pem', 'My Custom CA', None), cache=certStore)

   (filename,) = ca['example.com']

In this configuration, the root CA is stored at ``my-ca.pem`` and dynamically generated certs
are placed in ``/tmp/certs``. The ``filename`` returned would be ``/tmp/certs/example.com.pem`` in this example.

This filename can then be used with the Python `ssl.load_cert_chain(certfile) <https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_cert_chain>`_ command.

Note that the dynamically created certs are never deleted by ``certauth``, it remains up to the user to handle cleanup occasionally if desired.


In-memory Certificate Cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   from certauth2 import CertificateAuthority
   ca = CertificateAuthority(
      ("My Custom CA", "my-ca.pem", None), cache=50
   )
   cert, key, chain = ca["example.com"].to_pyopenssl()
   
This configuration stores the root CA at ``my-ca.pem`` but uses an in-memory certificate cache for dynamically created certs. 
By default the default store returns X509Credentials which are just a NamedTuple of (cert, key, chain) in ``cryptography`` format with methods to help load, dump and transform them into other formats.

These certs are stored in an LRU cache, configured to keep at most 50 certs.

The ``cert`` and ``key`` can then be used with `OpenSSL.SSL.Context.use_certificate <http://www.pyopenssl.org/en/stable/api/ssl.html#OpenSSL.SSL.Context.use_certificate>`_

.. code:: python

        context = SSl.Context(...)
        context.use_privatekey(key)
        context.use_certificate(cert)
        for ca in chain:
         context.add_extra_chain_cert(ca)

Custom Cache
~~~~~~~~~~~~

A custom cache implementations which stores and retrieves per-host certificates can also be provided:

.. code:: python

   from certauth2 import CertificateAuthority
   from certauth2.cache import Cache

   class CustomCache(Cache):
      def __init__(
         self,
         transform = lambda x: x,
      ):
         self._cache = {}
         self._transform = transform

      def __setitem__(self, key, item):
         key = self._stored_as(key)
         self._cache[key] = self._transform(item)
      
      def __getitem__(self, key):
         key = self._stored_as(key)
         return self._cache[key]

   ca = CertificateAuthority('my-ca.pem', cache=CustomCache())
   creds = ca['example.com']


Wildcard Certs
~~~~~~~~~~~~~~
To reduce the number of certs generated, it is convenient to generate wildcard certs.
For full functionality also install tld library

.. code:: python

   creds = ca.load_creds('test.example.com', domain_cert=True)

This will generate a cert for ``*.example.com``.

.. code:: python

   creds = ca.load_creds('test.example.com', sans=["*.test.example.com"])

This will also generate a cert for ``*.test.example.com`` and ``test.example.com``

.. code:: python

   creds = ca.load_creds('test.example.com', domain_cert=True, sans=["*.test.example.com"])

This will also generate a cert for ``*.test.example.com``, ``test.example.com`` and ``*.example.com``

Alternative FQDNs or IPs in SAN
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes, you want to add alternative FQDNs or IPs as Subject Alternative Names
to your certificate. To do that, simply use the ``sans`` params:

.. code:: python

   creds = ca.load_cert('example.com', sans=['example.org','192.168.1.1'])

This will generate a cert for ``example.com`` with ``example.org`` and ``192.168.1.1`` in
the SAN.

Each san can be an ip as ``str|IPv4Address|IPv6Address`` a dns as ``str`` or ``x509.GeneralName``


CLI Usage Examples
==================

``certauth`` also includes a simple command-line API for certificate creation and management.

::

   usage: __main__.py [-h] [-c ISSUERNAME] [--issuerpass ISSUERPASS] [-n HOSTNAME] [-d CERTS_DIR] [-f] [-S SANS] issuer

   Certificate Authority Cert Maker Tools

   positional arguments:
   issuer                Path to existing CA or for a new root CA file

   optional arguments:
   -h, --help            show this help message and exit
   -c ISSUERNAME, --issuername ISSUERNAME
                           Name for issuer CA certificate
   --issuerpass ISSUERPASS
                           Issuer cert file password
   -n HOSTNAME, --hostname HOSTNAME
                           Hostname certificate to create
   -d CERTS_DIR, --certs-dir CERTS_DIR
                           Directory for host certificates
   -f, --force           Overwrite certificates if they already exist
   -S SANS, --sans SANS  add Subject Alternate Name to the cert



To create a new root CA certificate:

``certauth myrootca.pem --issuername "My Test CA"``

To create a host certificate signed with CA certificate in directory ``certs_dir``:

``certauth myrootca.pem --hostname "example.com" -d ./certs_dir``

If the root cert doesn't exist, it'll be created automatically.
If ``certs_dir``, doesn't exist, it'll be created automatically also.

The cert for ``example.com`` will be created as ``certs_dir/example.com.pem``.
If it already exists, it will not be overwritten (unless ``-f`` option is used).

The ``-w`` option can be used to create a wildcard cert which has subject alternate names (SAN) for ``example.com`` and ``*.example.com``