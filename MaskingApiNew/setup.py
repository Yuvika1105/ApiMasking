from setuptools import setup, find_packages

setup(
    name="safeguard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "presidio-analyzer",
        "presidio-anonymizer",
        "spacy",
        "en_core_web_lg @ https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl"
    ],
    description="Enterprise PII Masking Engine",
)
