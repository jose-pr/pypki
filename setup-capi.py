from setup_init import *

setup(name='openssl_engine_capi',
      version='1.0',
      description='Python capi openssl engine support and utility methods to set a default for urllib3 and pip',
      author='Jose A.',
      author_email='jose-pr@coqui.dev',
      url='https://github.com/jose-pr/pypki',
      package_dir = {'': 'src'},
      packages=['openssl_engine_capi'],
      install_requires=["openssl_engine"]
     )