import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="KeyCrypt",
    version="1.0.0",
    author="Akshay R. Kapadia",
    author_email="akshayrkapadia@tutamail.com",
    description="Secure Password Manager With GPG Encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/akshayrkapadia/KeyCrypt",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ),
)
