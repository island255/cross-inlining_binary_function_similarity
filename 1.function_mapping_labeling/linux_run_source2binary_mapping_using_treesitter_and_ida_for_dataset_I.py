import json
from functools import partial
from multiprocessing import Pool
from tqdm import tqdm
from linux_run_sub_functions import extract_mapping_information_dispatcher
from tree_sitter_scripts import use_tree_sitter_get_function_ranges
from extract_debug_information import extract_debug_dump
from mapping import binary2source_mapping
import os
import csv

import platform

if platform.system().lower() == 'windows':
    platform_separator = "\\"
    substitute_separator = "/"
elif platform.system().lower() == 'linux':
    platform_separator = "/"
    substitute_separator = "\\"


def read_binary_list(projectdir):
    """
    get all binary file's path
    """
    binary_paths = []
    for root, dirs, files in os.walk(projectdir):
        for file_name in files:
            if file_name.endswith(".elf"):
                file_path = os.path.join(root, file_name)
                binary_paths.append(file_path)
    return binary_paths


def extract_mapping_information(binary_project_dir, source_entities_file, flowchart_dir,
                                debug_dir, mapping_dir, c_file_path_list, readelf_file_path):
    with open(source_entities_file, "r") as f:
        source_entities_info = json.load(f)
    binary_paths = read_binary_list(binary_project_dir)
    project_name = os.path.basename(binary_project_dir)
    arguments_list = []
    for binary_path in binary_paths:
        binary_name = os.path.basename(binary_path)
        binary_range_file = os.path.join(flowchart_dir, binary_name + ".i64.csv")
        result_dir = os.path.join(debug_dir, project_name)
        debug_file = os.path.join(result_dir, binary_name)
        arguments_list.append([binary_path, project_name, binary_range_file, source_entities_info, debug_file,
                               binary_name, mapping_dir, c_file_path_list, result_dir, readelf_file_path])
    # with Pool(processes=6) as pool:
    #     _partial_func = partial(extract_mapping_information_dispatcher)
    #     pool.map(_partial_func, arguments_list)
    p = Pool(12)
    with tqdm(total=len(arguments_list)) as pbar:
        for i, res in tqdm(enumerate(p.imap_unordered(extract_mapping_information_dispatcher, arguments_list))):
            pbar.update()
    p.close()
    p.join()


def main():
    binary_projects_dir = "/path/to/binary2binary/dataset_I/"
    debug_dir = os.path.join(binary_projects_dir, "debug_infos")
    source_entities_dir = os.path.join(binary_projects_dir, "source_entities")
    mapping_dir = os.path.join(binary_projects_dir, "mapping_results")

    readelf_file_path = "readelf"
    tree_sitter_lib_path = "tree_sitter_scripts/my-languages.so"

    source_project_folder = "/path/to/binary2binary/dataset_I/source/"
    binary_project_folder = "/path/to/binary2binary/Binaries/Dataset-1/"

    flowchart_dir = "/path/to/binary2binary/IDA_scripts/IDA_flowchart/flowchart_csv_dataset_I"

    project_name_list = os.listdir(binary_project_folder)
    for project_name in project_name_list:
        print(" processing project: {} num: {} of total {}".format(project_name,
                                                                   str(project_name_list.index(project_name) + 1),
                                                                   str(len(project_name_list))))
        source_project_dir = os.path.join(source_project_folder, project_name)
        binary_project_dir = os.path.join(binary_project_folder, project_name)
        # project_name = os.path.basename(source_project_dir)
        source_entities_result_dir = os.path.join(source_entities_dir, project_name)
        if os.path.exists(source_entities_result_dir) is False:
            os.makedirs(source_entities_result_dir)
        source_entities_file = os.path.join(source_entities_result_dir,
                                            project_name + "_function_range_content.json")
        c_file_path_list = use_tree_sitter_get_function_ranges.get_functions_ranges(source_project_dir,
                                                                                    source_entities_result_dir,
                                                                                    tree_sitter_lib_path)

        extract_mapping_information(binary_project_dir, source_entities_file, flowchart_dir,
                                    debug_dir, mapping_dir, c_file_path_list, readelf_file_path)


if __name__ == '__main__':
    main()
