"""Utility functions"""


def increment_database_version(database_version):
    """Increment database version
    note:: Only micro version is modified

    :return: incremented database string version

    >>> increment_database_version("(1, 2, 2)")
    '(1, 2, 3)'
    """
    database_version = database_version.replace("(", "").replace(")", "")
    database_version = database_version.split(", ")
    database_version[2] = str(int(database_version[2]) + 1)
    database_version = ", ".join(database_version)
    return "(" + database_version + ")"
