"""setup.py file."""
import setuptools

# read the contents of your README file
with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name = "napalm_aruba505",
    version = "0.0.168",
    author = "David Johnnes",
    author_email = "david.johnnes@gmail.com",
    description = ("Napalm Aruba driver for ArubaOS Wi-Fi devices '505' "),
    license = "Apache 2",
    keywords = "napalm drive",
    url="https://github.com/djohnnes/napalm-arubaOS",
    packages=['napalm_aruba505'],
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License",
    ],
)
