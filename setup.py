"""
Sentry Antivirus Setup Script
Always protects your computer!
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="sentry-antivirus",
    version="1.0.0",
    author="Sentry Security",
    author_email="sentryantivirus@gmail.com",
    description="🛡️ Sentry Antivirus",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LinkyJayy/sentry-antivirus",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: JayLink Technologies, Inc. :: LJ-OS :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
    install_requires=[
        "watchdog>=3.0.0",
        "psutil>=5.9.0",
        "customtkinter>=5.2.0",
        "Pillow>=10.0.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "sentry=main:main",
        ],
        "gui_scripts": [
            "sentry-gui=sentry.gui.app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["data/*.yaml"],
    },
)
