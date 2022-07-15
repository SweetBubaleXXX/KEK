from setuptools import setup, find_packages

setup(name="gnukek",
      version="0.2.1",
      description="Kinetic Effective Key",
      author="SweetBubaleXXX",
      license="GNU General Public License v3.0",
      url="https://github.com/SweetBubaleXXX/KEK",
      project_urls={
          "Source": "https://github.com/SweetBubaleXXX/KEK",
          "Bug Tracker": "https://github.com/SweetBubaleXXX/KEK/issues",
      },
      classifiers=[
          "DEVELOPMENT STATUS :: 3 - ALPHA",
          "TOPIC :: SECURITY :: CRYPTOGRAPHY",
          "Programming Language :: Python :: 3",
          "LICENSE :: OSI APPROVED :: GNU GENERAL PUBLIC LICENSE V3 (GPLV3)",
          "Operating System :: OS Independent",
      ],
      packages=find_packages(include=["KEK"]),
      install_requires=[
          "cryptography>=35.0.0"
      ],
      extras_require={
          "dev": [
              "mypy",
              "pycodestyle"
          ],
          "build": [
              "build",
              "twine"
          ]
      },
      python_requires=">=3.7",
      test_suite="tests")
