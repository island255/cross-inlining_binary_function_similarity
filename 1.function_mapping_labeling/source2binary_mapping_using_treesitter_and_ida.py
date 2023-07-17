import json

from tree_sitter_scripts import use_tree_sitter_get_function_ranges
from extract_debug_information import extract_debug_dump
from mapping import binary2source_mapping
import os
import csv

from tree_sitter_scripts.use_tree_sitter_get_function_ranges import write_json

import platform

if platform.system().lower() == 'windows':
    platform_separator = "\\"
    substitute_separator = "/"
elif platform.system().lower() == 'linux':
    platform_separator = "/"
    substitute_separator = "\\"


def extract_debug_information(binary_path, result_dir, readelf_file_path):
    """ this will generate line number mapping"""
    result_file_path = os.path.join(result_dir, os.path.basename(binary_path))
    if os.path.exists(result_file_path):
        return
    if os.path.exists(result_dir) is False:
        try:
            os.makedirs(result_dir)
        except:
            pass
    extract_debug_dump.extract_debug_dump_information(readelf_file_path, binary_path, result_dir)


def read_json(binary2source_file_entity_simple_mapping_file):
    """read json file from disk"""
    with open(binary2source_file_entity_simple_mapping_file, "r") as f:
        load_dict = json.load(f)
        return load_dict


def extract_source2binary_function_mapping(binary_range_file, source_entities_info, debug_file, project_name,
                                           binary_name, mapping_dir, c_file_path_list):
    """extend the line number mapping result to function level mapping result"""
    result_mapping_file_dir = os.path.join(mapping_dir, project_name)
    if os.path.exists(result_mapping_file_dir) is False:
        try:
            os.makedirs(result_mapping_file_dir)
        except:
            pass
    binary2source_function_mapping_file = os.path.join(result_mapping_file_dir, binary_name +
                                                       "_function_mapping.json")
    binary2source_line_mapping_file = os.path.join(result_mapping_file_dir, binary_name +
                                                   "_line_mapping.json")
    # if os.path.exists(binary2source_function_mapping_file) and os.path.exists(binary2source_line_mapping_file):
    #     binary2source_function_mapping = read_json(binary2source_function_mapping_file)
    #     if binary2source_function_mapping:
    #         return

    source2binary_mapping_full = binary2source_mapping.extract_entity_mapping(binary_range_file, source_entities_info,
                                                                              debug_file, c_file_path_list)
    binary2source_function_mapping = \
        binary2source_mapping.get_binary2source_entity_mapping(source2binary_mapping_full)

    write_json(binary2source_line_mapping_file, source2binary_mapping_full)
    write_json(binary2source_function_mapping_file, binary2source_function_mapping)
