from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Define test dependencies
test_requirements = [
    "pytest>=8.0.0",
    "pytest-cov>=6.0.0",
    "pytest-qt>=4.4.0",
    "pytest-mock>=3.14.0",
    "pytest-xdist>=3.6.1",
    "pytest-asyncio>=0.25.3",
]

setup(
    name="lcg-password-manager",
    version="1.0.0",
    author="Nicholas Grant",
    description="Enterprise-grade password management solution",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/lcg-password-manager",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "test": test_requirements,
        "dev": test_requirements + [
            "black>=23.7.0",
            "flake8>=6.1.0",
            "isort>=5.12.0",
            "mypy>=1.5.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "lcg-password-manager=lcg_password_manager.__main__:main",
        ],
    },
) 