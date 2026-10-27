"""Rules that read only PyPI's information about a release, never its code.

    typosquat           a name one or two typos from a popular package
    new_package         a package created days (or hours) before this release
    sdist_only          no wheel, so installing always runs setup.py
    no_project_links    no homepage or repository link
    missing_metadata    no summary and no author
    suspicious_links    links to raw IPs, URL shorteners, paste sites
    late_file_upload    a file added to a release long after the first

Each is weak alone; scoring adds them up with the code rules.
"""
