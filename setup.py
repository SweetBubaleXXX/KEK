from setuptools import setup, find_packages

setup(name="kek",
      version="0.1.0",
      description="Kinetic Effective Key",
      url="https://github.com/SweetBubaleXXX/KEK.git",
      author="SweetBubaleXXX",
      author_email="1pcpcpc1pc@gmail.com",
      license="GNU General Public License v3.0",
      packages=find_packages(include=["KEK"]),
      install_requires=[
          "cryptography>=36.0.0"
      ],
      python_requires=">=3.7")

