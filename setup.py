from setuptools import setup

setup(name='oauthpylons',
    version='0.1',
    description='This is an OAuth controller and helpers for the Pylons web framework.',
    author='Tadas Vilkeliskis',
    author_email='vilkeliskis.t@gmail.com',
    url='https://github.com/tadasv/oauth-pylons',
    install_requires = ["oauth2", "Pylons"],
    packages=['oauthpylons']
)
