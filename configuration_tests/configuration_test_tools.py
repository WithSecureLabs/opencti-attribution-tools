import argparse
import os
import re
import shlex
from functools import reduce
from pathlib import Path

import yaml
from jinja2cli import cli

from attribution_tools.pyspark_main import parse_args as main_arg_parser

# Matches alphanumeric parameter names with dashes/underscores and dots surrounded by '${...}' and
# captures the parameter name.
PARAM_TEMPLATE_RE = re.compile(r"\${([a-zA-Z0-9\-_.]+)}")

# Matches alphanumeric flow names with underscores/dashes. A "'" might be present to end a shell command and
# captures the flow name.
FLOW_NAME_RE = re.compile(r"\s+FLOW=([a-zA-Z0-9\-_]+)'?\s+")


def find_jinja2_flows_in_jenkinsfile():
    """Looks for 'FLOW=flow_name' phrases in Jenkinsfile to determine flow names.

    :return: list of flow names mentioned in Jenkinsfile.
    """
    flows = set()
    jenkinsfile_path = relative_to_project_root("Jenkinsfile")
    if jenkinsfile_path.exists():
        with open(jenkinsfile_path, "r") as jenkinsfile:
            for occurrence in FLOW_NAME_RE.finditer(jenkinsfile.read()):
                flows.add(occurrence.groups()[0])
    return list(flows)


def get_cmdlns_from_template(template_path, deployment_type):
    """Returns the command lines defined in the template where the template parameters
    have been substituted.

    :param template_path: file path of the template.
    :param deployment_type: deployment environment, for template rendering.
    :return: list of command lines without parameters.
    """
    command_lines = set()
    rendered_flow = render_to_dict(file_path=template_path, deployment_type=deployment_type)

    template_params = get_config_from_rendered_template(rendered_flow)
    template_cmdlns = get_cmdlns_from_rendered_template(rendered_flow)

    for cmdln in template_cmdlns:
        actual_cmd_line = substitute_cmdln_parameters(cmdln, template_params)
        command_lines.add(actual_cmd_line)
    return list(command_lines)


def get_cmdlns_from_rendered_template(rendered_template):
    """Returns the list of command line found in this Jinja2 rendered template. Command lines must be
    defined in the nodes of the flow under the config section.

    :param rendered_template: dictionary containing a rendered jinja2 template.
    :return: list of command lines.
    """
    command_lines = set()
    if "nodes" in rendered_template:
        for node in rendered_template["nodes"]:
            if "config" in node and "command" in node["config"]:
                command_lines.add(node["config"]["command"])
    return list(command_lines)


def get_config_from_rendered_template(rendered_template):
    """Returns the config section in the rendered template.

    :param rendered_template: dictionary containing a rendered jinja2 template.
    :return: dictionary containing config section of the template.
    """
    return rendered_template["config"]


def split_cmdln(cmdln):
    """Split command line string usig shell-like syntax.

    :param cmdln: Command line string.
    :return: List containing splitted command line.

    Examples:

    >>> split_cmdln("echo Hello, world!")
    ['echo', 'Hello,', 'world!']
    >>> split_cmdln("")
    []
    """
    return shlex.split(cmdln)


def relative_to_project_root(input_path):
    """Returns the input path as a path relative to the project root.

    :param input_path: original path.
    :return: pathlib.Path relative to the project root
    """
    return Path(__file__).parent / ".." / input_path


def render_to_dict(file_path, deployment_type):
    """Renders a jinja2 flow template to a dict. What is more, as we are trying to simulate job building by Azkaban,
    azkaban.flow.execid and version is added to the dictonary.

    :param file_path: Full path to a jinja2 flow file.
    :param deployment_type: Should be in ("staging", "production)
    :return: Dictionary containing rendered jinja2 flow.
    """
    os.environ["CONFIG"] = deployment_type
    os.environ["DEPLOYMENTTYPE"] = deployment_type
    os.environ["PROJECT_NAME"] = "project-name-stub"

    flow_rendered = cli.render(file_path, {}, [])
    flow_loaded = yaml.load(flow_rendered, Loader=yaml.FullLoader)
    flow_loaded["config"]["version"] = "project-version-stub"
    flow_loaded["config"]["azkaban.flow.execid"] = "azkaban-flow-id-stub"

    return flow_loaded


def _param_references_present(param_dict):
    for param_name in param_dict.keys():
        param_name_references = [f"${{{param_name}}}" in str(param_value) for param_value in param_dict.values()]
        if any(param_name_references):
            return True
    return False


def check_if_recursive_param_reference_present(param_dict):
    for param_name, param_value in param_dict.items():
        is_recursive = f"${{{param_name}}}" in str(param_value)
        if is_recursive:
            raise ValueError(f"Recursive reference found, while normalizing parameter dict:\n {param_dict}")


def normalize_param_dict(param_dict):
    """Replaces the value of parameters that refers to other parameters in the parameter dictionary.

    Our build support parameter value referring to other parameters, e.g.

    base_dir: my/path
    my_file: ${base_dir}/file.txt

    This function substitutes the correct values.
    Returns None as it normalizes the param_dict in place.

    :param param_dict: dictionary containing parameter names and values.
    :return: None
    """
    while _param_references_present(param_dict):
        check_if_recursive_param_reference_present(param_dict)
        for param_name, original_value in param_dict.items():
            substituted_value = original_value
            for match in PARAM_TEMPLATE_RE.finditer(str(original_value)):
                param_reference = match.groups()[0]
                substituted_value = substituted_value.replace(f"${{{param_reference}}}", param_dict[param_reference])
            if substituted_value != original_value:
                param_dict[param_name] = substituted_value


def substitute_cmdln_parameters(cmdln, param_dict):
    """Substitutes placeholders in command line with the values in param_dict.
    Returns the substituted command line.

    Placeholders are in the form ${param-name}.

    :param cmdln: string representing a command line with optional parameter placeholders.
    :param param_dict: dict containing parameter names and values.
    :return: string representing the substituted command line.
    """
    for param_template in PARAM_TEMPLATE_RE.finditer(cmdln):
        param_name = param_template.groups()[0]
        if param_name not in param_dict:
            raise ValueError("Parameter {} required in '{}' is not defined.".format(param_name, cmdln))

    for param_name, param_value in param_dict.items():
        cmdln = cmdln.replace("${" + param_name + "}", str(param_value))
    return cmdln


def get_main_arguments_from_cmdln(cmdln):
    """Returns the arguments of the main.py script in the command line. If main.py is not in the command line
    returns None.

    :param cmdln: string representing a command line
    :return: list of arguments to the main.py script, or the None.
    """
    if "main.py" in cmdln:
        before, arguments = cmdln.split("main.py")
        return split_cmdln(arguments)
    else:
        return None


def parse_arguments(arguments):
    """Uses the arg_parser defined in main.py to parse the argument list.
    Exceptions raised are caught by the caller to determine if parsing was successful.

    :param arguments: list of command line arguments.
    :return: None
    """
    argparse.ArgumentParser.parse_args.__defaults__ = (arguments, None)
    main_arg_parser()


class ConfigurationTestTools:
    """Implements utility functions to test the project parameter configuration and build."""

    def __init__(
        self,
        obligatory_job_params=None,
        optional_spark_params=None,
        azkaban_template_dir="azkaban_templates/",
        main_filename="main.py",
    ):
        if obligatory_job_params is None:
            obligatory_job_params = [
                "emr.MasterFleetInstanceType1",
                "emr.CoreFleetInstanceType1",
                "emr.CoreFleetInstanceWeight1",
                "emr.terminateOnFailure",
                "tag.contact",
                "tag.costcenter",
                "s3project_path",
            ]

        if optional_spark_params is None:
            optional_spark_params = []

        self.obligatory_job_params = obligatory_job_params
        self.optional_spark_params = optional_spark_params
        self.azkaban_template_dir = azkaban_template_dir
        self.main_filename = main_filename
        self.inst_cmdlns_list = []

    def find_jinja2_templates(self):
        """Finds all file names in the Azkaban template directory that will be rendered by Jinja2.

        :return: List of strings representing Jinja2 template files
        """
        absolute_template_dir = relative_to_project_root(self.azkaban_template_dir)
        return [
            str(file_path) for file_path in absolute_template_dir.iterdir() if file_path.name.endswith(".flow.jinja2")
        ]

    def get_all_main_arguments(self, deployment_type):

        main_arguments = []
        for template_path in self.find_jinja2_templates():
            for cmdln in get_cmdlns_from_template(template_path, deployment_type):
                main_arguments.append(get_main_arguments_from_cmdln(cmdln))
        return main_arguments

    def get_all_parameters(self, deployment_type):

        flow_templates_paths = self.find_jinja2_templates()

        flow_configs = {}
        for template_path in flow_templates_paths:
            rendered_flow = render_to_dict(file_path=template_path, deployment_type=deployment_type)
            flow_configs[template_path] = get_config_from_rendered_template(rendered_flow)

        # Merge all parameters into a single dict, more recent values are overwritten
        all_parameters = reduce(lambda dict1, dict2: {**dict1, **dict2}, flow_configs.values())

        # Resolve recursive parameter references
        normalize_param_dict(all_parameters)

        return all_parameters

    def get_parameters_by_key_matching(self, regexp, deployment_type):
        all_params = self.get_all_parameters(deployment_type)
        filtered_params = {}
        for k, v in all_params.items():
            if re.match(regexp, k):
                filtered_params[k] = v
        return filtered_params

    def get_parameters_by_value_matching(self, regexp, deployment_type):
        all_params = self.get_all_parameters(deployment_type)
        filtered_params = {}
        for k, v in all_params.items():
            if re.match(regexp, str(v)):
                filtered_params[k] = v
        return filtered_params
