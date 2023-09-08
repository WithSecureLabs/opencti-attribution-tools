#!/usr/bin/env python3
"""Application entry point."""
import argparse
import json
import logging
from typing import Any, Dict

from pyspark.sql import SparkSession


def configure_logging(config: Dict[str, Any], log_name: str = "opencti_attribution_tools") -> logging.Logger:
    """Configures logging format and returns the application logger.

    :param conf: application configuration dictionary.
    :param log_name: name of the application logger.
    :return: application logger.
    """
    logging.basicConfig()
    root_logger = logging.getLogger()
    root_logger.setLevel(config["log_level"])
    formatter = logging.Formatter("%(asctime)-15s %(levelname)s %(name)s:%(lineno)d: %(message)s")
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)

    return logging.getLogger(log_name)


def remove_none_values(config: Dict[str, Any]) -> Dict[str, Any]:
    """Removes the keys whose value is None from the input dict.

    Examples:

    >>> a = {"x": 1, "y": None, "z": "hello"}
    >>> remove_none_values(a)
    {'x': 1, 'z': 'hello'}

    :param config: input dict with None values.
    :return: output dict without None values.
    """
    return {k: v for k, v in config.items() if v is not None}


def parse_args() -> Dict[str, Any]:
    """Parses CLI arguments into a configuration dictionary."""
    parser = argparse.ArgumentParser(description="OpenCTI Attribution Tools Model.")
    parser.add_argument(
        "-l",
        "--log-level",
        help="Logging level.",
        dest="log_level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    parser.add_argument(
        "--base-url",
        dest="base_url",
        help="Base S3 URL under which the model and other outputs of the pipeline are stored.",
        type=str,
    )
    config = vars(parser.parse_args())
    return remove_none_values(config)


def print_config_values(config: Dict[str, Any], logger: logging.Logger) -> None:
    """Pretty prints the application configuration."""
    logger.info("Config: %s", json.dumps(config, indent=4, default=str))


def get_spark_session(app_name: str = "Attribution Tools model") -> SparkSession:
    """Gets a singleton SparkSession.

    The SparkSession is created using getOrCreate() meaning Spark will handle
    the singleton instances.

    :param app_name: the application name for the SparkConf
    """
    spark = SparkSession.builder.appName(app_name).enableHiveSupport().getOrCreate()

    spark.conf.set("spark.sql.adaptive.enabled", "false")
    spark.conf.set("spark.sql.caseSensitive", "true")
    spark.sparkContext.setLogLevel("WARN")

    return spark


def main():
    """Main application entry point."""
    config = parse_args()
    logger = configure_logging(config)

    config["spark"] = get_spark_session()

    print_config_values(config, logger)


if __name__ == "__main__":
    main()
