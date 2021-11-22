from setup_init import *

setup(name='openssl_engine_capi',
      version='1.0',
      description='Python openssl engine support',
      author='Jose A.',
      author_email='jose-pr@coqui.dev',
      url='',
      package_dir = {'': 'src'},
      packages=['openssl_engine_capi'],
      install_requires=["openssl_engine"]
     )