from setuptools import setup, find_packages

setup(name="kek",
      version="0.1.1",
      description="Kinetic Effective Key",
      url="https://github.com/SweetBubaleXXX/KEK",
      author="SweetBubaleXXX",
      license="GNU General Public License v3.0",
      packages=find_packages(include=["KEK"]),
      install_requires=[
          "cryptography>=35.0.0"
      ],
      python_requires=">=3.7",
      test_suite="tests")
