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
          "Development Status :: 3 - Alpha",
          "Topic :: Security :: Cryptography",
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          "Programming Language :: Python :: 3",
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
