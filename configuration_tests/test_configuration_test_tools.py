from pathlib import Path
from unittest import TestCase

from configuration_tests.configuration_test_tools import (
    get_main_arguments_from_cmdln,
    normalize_param_dict,
    relative_to_project_root,
    substitute_cmdln_parameters,
)


class ConfigurationTestToolsTests(TestCase):

    project_root_dir = Path(__file__).parent / ".."

    def test_relative_to_project_root_with_empty_path(self):
        self.assertEqual(relative_to_project_root(""), self.project_root_dir)

    def test_relative_to_project_root_with_simple_file(self):
        file_name = "dummy_file.txt"
        self.assertEqual(relative_to_project_root(file_name), self.project_root_dir / file_name)

    def test_relative_to_project_root_with_full_path_(self):
        sample_path = "this/is/a/path.txt"
        self.assertEqual(relative_to_project_root(sample_path), self.project_root_dir / sample_path)

    def test_get_main_arguments_from_cmdln_where_cmdln_is_empty(self):
        self.assertEqual(get_main_arguments_from_cmdln(""), None)

    def test_get_main_arguments_from_cmdln_where_cmdln_does_not_contain_main(self):
        self.assertEqual(get_main_arguments_from_cmdln("echo hello, world"), None)

    def test_get_main_arguments_from_cmdln_where_main_has_no_arguments(self):
        self.assertEqual(get_main_arguments_from_cmdln("python main.py"), [])

    def test_get_main_arguments_from_cmdln_where_cmdln_is_valid(self):
        valid_cmdln = "ps aux | python main.py --argument value --flag"

        self.assertEqual(get_main_arguments_from_cmdln(valid_cmdln), ["--argument", "value", "--flag"])

    def test_substitute_cmdln_parameters_when_there_are_parameters(self):
        parameters = {"int_parameter": 123, "string_parameter": "hello"}
        template_cmd_line = "main.py --int-arg ${int_parameter} --str-arg ${string_parameter}"

        expected_cmd_line = "main.py --int-arg 123 --str-arg hello"

        self.assertEqual(expected_cmd_line, substitute_cmdln_parameters(template_cmd_line, parameters))

    def test_substitute_cmdln_parameters_when_there_are_no_substitutions(self):
        parameters = {"int_parameter": 123, "string_parameter": "hello"}
        template_cmd_line = "main.py --int-arg 456 --str-arg world"
        expected_cmd_line = template_cmd_line

        self.assertEqual(expected_cmd_line, substitute_cmdln_parameters(template_cmd_line, parameters))

    def test_substitute_cmdln_parameters_when_cmdln_is_empty(self):
        parameters = {"int_parameter": 123, "string_parameter": "hello"}
        template_cmd_line = ""
        expected_cmd_line = template_cmd_line

        self.assertEqual(expected_cmd_line, substitute_cmdln_parameters(template_cmd_line, parameters))

    def test_substitute_cmdln_parameters_raises_exception_when_there_are_no_parameters(self):
        parameters = {}
        template_cmd_line = "main.py --int-arg ${int_parameter} --str-arg ${string_parameter}"

        with self.assertRaises(ValueError):
            substitute_cmdln_parameters(template_cmd_line, parameters)

    def test_substitute_cmdln_parameters_raises_exception_with_undefined_parameters(self):
        parameters = {"invalid_parameter": 123}
        template_cmd_line = "main.py --int-arg ${int_parameter} --str-arg ${string_parameter}"

        with self.assertRaises(ValueError):
            substitute_cmdln_parameters(template_cmd_line, parameters)

    def test_normalize_param_dict_key_order1(self):
        param_dict = {"a": "${b}", "b": "${c}", "c": "value"}
        expected_value = {"a": "value", "b": "value", "c": "value"}
        normalize_param_dict(param_dict)
        self.assertEqual(expected_value, param_dict)

    def test_normalize_param_dict_key_order2(self):
        param_dict = {"b": "${c}", "a": "${b}", "c": "value"}
        expected_value = {"a": "value", "b": "value", "c": "value"}
        normalize_param_dict(param_dict)
        self.assertEqual(expected_value, param_dict)

    def test_normalize_param_dict_raises_exception_with_recursive_param_dict_simple(self):
        param_dict = {"a": "${a}"}
        with self.assertRaises(ValueError):
            normalize_param_dict(param_dict)

    def test_normalize_param_dict_raises_exception_with_recursive_param_dict_loop(self):
        param_dict = {"a": "${b}", "b": "${a}"}
        with self.assertRaises(ValueError):
            normalize_param_dict(param_dict)
