from setuptools import setup, find_packages

setup(
    name="auditguard",
    version="1.0.0",
    description="Python client for AuditGuard — Technical & Cybersecurity Audit API",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="AuditGuard",
    url="https://auditguard.ru",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["requests>=2.28.0"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
)
