from setuptools import setup, find_namespace_packages

setup(
    name="pysigma-backend-qualys",
    version="0.1.0",
    packages=find_namespace_packages(include=["sigma.*"]),
    install_requires=[
        "pysigma>=0.9.0",
    ],
    url="https://github.com/YourUsername/pysigma-backend-qualys",
    author="Your Name",
    author_email="your.email@example.com",
    description="Qualys backend for Sigma rule processing",
)