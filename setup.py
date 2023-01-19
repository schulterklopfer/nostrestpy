from setuptools import setup

setup(
    # Needed to silence warnings (and to be a worthwhile package)
    name='Nostrestpy',
    url='https://github.com/schulterklopfer/nostrestpy',
    author='SKP',
    author_email='',
    # Needed to actually package something
    packages=['nostrest'],
    # Needed for dependencies
    install_requires=['pycryptodomex', 'nostr'],
    dependency_links=['git+https://github.com/schulterklopfer/python-nostr.git'],
    # *strongly* suggested for sharing
    version='0.1',
    # The license can be anything you like
    license='MIT',
    description='',
    # We will also need a readme eventually (there will be a warning)
    # long_description=open('README.txt').read(),
)