import os
import platform

from source2binary_mapping_using_treesitter_and_ida import  extract_debug_information, \
    extract_source2binary_function_mapping

if platform.system().lower() == 'windows':
    platform_separator = "\\"
    substitute_separator = "/"
elif platform.system().lower() == 'linux':
    platform_separator = "/"
    substitute_separator = "\\"


def extract_mapping_information_dispatcher(auguments):
    binary_path, project_name, binary_range_file, source_entities_info, debug_file, \
    binary_name, mapping_dir, c_file_path_list, result_dir, readelf_file_path = auguments
    # extract_binary_function_range(binary_path, project_dir, project_name, Ghidra_path, script_path)
    if os.path.exists(binary_range_file) is False:
        print("cannot find the binary range file")
        return
    extract_debug_information(binary_path, result_dir, readelf_file_path)
    extract_source2binary_function_mapping(binary_range_file, source_entities_info, debug_file, project_name,
                                           binary_name, mapping_dir, c_file_path_list)
