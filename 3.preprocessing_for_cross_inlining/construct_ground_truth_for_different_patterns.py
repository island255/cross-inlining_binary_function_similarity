import csv
import json
import os
import pickle
import random
import shutil
from tqdm import tqdm


def read_json(file_path):
    with open(file_path, "r") as f:
        file_content = json.load(f)
        return file_content


def write_json(file_path, obj):
    with open(file_path, "w") as f:
        json_str = json.dumps(obj, indent=2)
        f.write(json_str)


def read_pickle(file_path):
    with open(file_path, "rb") as f:
        return pickle.load(f)


def get_binary_function_mapped_source_functions(mapping_file_content, source_prefix):
    function_mappings = {}
    for binary_function in mapping_file_content:
        if mapping_file_content[binary_function]:
            function_mappings[binary_function] = []
            mapped_source_function_list = mapping_file_content[binary_function]
            for mapped_source_function in mapped_source_function_list:
                source_file, source_function, source_function_range = mapped_source_function
                source_file = source_file.replace(source_prefix, "")
                source_function_start_line, source_function_end_line = source_function_range
                source_function_key = "+".join([source_file, source_function, str(source_function_start_line)])
                if source_function_key not in function_mappings[binary_function]:
                    function_mappings[binary_function].append(source_function_key)
    return function_mappings


def get_source_function_mapped_normal_functions(binary_i64_to_function_mapping):
    source_function_key_to_binary_functions = {}
    for project_name in binary_i64_to_function_mapping:
        print("    processing project {}".format(project_name))
        if project_name not in source_function_key_to_binary_functions:
            source_function_key_to_binary_functions[project_name] = {}
        project_binary_mappings = binary_i64_to_function_mapping[project_name]
        for binary_i64 in project_binary_mappings:
            BF_to_SF_mapping_dict = project_binary_mappings[binary_i64]
            for BF in BF_to_SF_mapping_dict:
                SF_list = BF_to_SF_mapping_dict[BF]
                if len(SF_list) == 1:
                    SF = SF_list[0]
                    if SF not in source_function_key_to_binary_functions[project_name]:
                        source_function_key_to_binary_functions[project_name][SF] = \
                            {"equal": [[binary_i64, BF]], "partial": []}
                    else:
                        if [binary_i64, BF] not in source_function_key_to_binary_functions[project_name][SF]["equal"]:
                            source_function_key_to_binary_functions[project_name][SF]["equal"].append([binary_i64, BF])
                else:
                    continue
    return source_function_key_to_binary_functions


def extract_inlined_function_mapping(source_function_key_to_binary_functions):
    inlined_function_mappings = {}
    for project_name in source_function_key_to_binary_functions:
        project_mappings = source_function_key_to_binary_functions[project_name]
        for source_function_key in project_mappings:
            if project_mappings[source_function_key]["partial"]:
                if project_name not in inlined_function_mappings:
                    inlined_function_mappings[project_name] = {}
                inlined_function_mappings[project_name][source_function_key] = \
                    project_mappings[source_function_key]["partial"]
    return inlined_function_mappings


def summary_statistics(source_function_key_to_binary_functions):
    different_source_function_count = {"equal": 0, "partial": 0, "both": 0}
    positive_pairs = 0
    for project_name in source_function_key_to_binary_functions:
        project_mappings = source_function_key_to_binary_functions[project_name]
        for source_function_key in project_mappings:
            if project_mappings[source_function_key]["equal"] and project_mappings[source_function_key]["partial"]:
                different_source_function_count["both"] += 1
                positive_pairs += len(project_mappings[source_function_key]["equal"]) * \
                                  len(project_mappings[source_function_key]["partial"])
            elif project_mappings[source_function_key]["equal"]:
                different_source_function_count["equal"] += 1
            elif project_mappings[source_function_key]["partial"]:
                different_source_function_count["partial"] += 1
            else:
                raise Exception
    print(different_source_function_count)
    print(positive_pairs)


def extract_key_mapped_dicts(inlined_function_mappings, train_set_keys):
    select_set = {}
    for key in train_set_keys:
        if key not in inlined_function_mappings:
            continue
        select_set[key] = inlined_function_mappings[key]
    return select_set


def generate_split_dataset(acfg_disasm_folder, dest_split_fodler, train_set_keys, test_set_keys, validate_set_keys):
    train_acfg_disasm_folder = os.path.join(dest_split_fodler, "training", "acfg_disasm_Dataset-1_training")
    test_acfg_disasm_fodler = os.path.join(dest_split_fodler, "testing", "acfg_disasm_Dataset-1_testing")
    validate_acfg_disasm_fodler = os.path.join(dest_split_fodler, "validation", "acfg_disasm_Dataset-1_validation")
    for disasm_folder in [train_acfg_disasm_folder, test_acfg_disasm_fodler, validate_acfg_disasm_fodler]:
        if os.path.exists(disasm_folder):
            os.rmdir(disasm_folder)
        os.makedirs(disasm_folder)
    for file_name in tqdm(os.listdir(acfg_disasm_folder)):
        file_path = os.path.join(acfg_disasm_folder, file_name)
        project_name = file_name.split("-")[0]
        if project_name in train_set_keys:
            shutil.copy(file_path, train_acfg_disasm_folder)
        if project_name in test_set_keys:
            shutil.copy(file_path, test_acfg_disasm_fodler)
        if project_name in validate_set_keys:
            shutil.copy(file_path, validate_acfg_disasm_fodler)


def extract_binary_functions_from_mapping(train_set):
    all_training_funcs = {}
    for project_name in train_set:
        for source_function_key in train_set[project_name]:
            for binary_function_type in train_set[project_name][source_function_key]:
                binary_function_tuple_list = train_set[project_name][source_function_key][binary_function_type]
                for binary_function_tuple in binary_function_tuple_list:
                    binary_name, function_address = binary_function_tuple
                    if binary_name not in all_training_funcs:
                        all_training_funcs[binary_name] = []
                    if function_address not in all_training_funcs[binary_name]:
                        all_training_funcs[binary_name].append(function_address)
    return all_training_funcs


def count_for_max_number(validate_set):
    max_number = 0
    for source_function_key in validate_set:
        equal_functions = validate_set[source_function_key]["equal"]
        partial_functions = validate_set[source_function_key]["partial"]
        max_number += len(equal_functions) * len(partial_functions)
    return max_number


def remove_project_key(validate_set):
    stripped_validate_set = {}
    for project_name in validate_set:
        stripped_validate_set = {**stripped_validate_set, **validate_set[project_name]}
    return stripped_validate_set


def write_to_pairs_csv(positive_path, selected_positive_pairs):
    csv_writer = csv.writer(open(positive_path, "w", newline=""))
    header = ["", "idb_path_1", "fva_1", "idb_path_2", "fva_2"]
    csv_writer.writerow(header)
    for index, pair in enumerate(selected_positive_pairs):
        f1, f2 = pair
        line = [index] + f1 + f2
        csv_writer.writerow(line)


def select_binary_function_in_same_compilation(f1, partial_list):
    f2 = None
    f1_binary_name = f1[0].split("/")[-1]
    for binary_function in partial_list:
        binary_name = binary_function[0].split("/")[-1]
        if binary_name == f1_binary_name:
            f2 = binary_function
            return f2
    return f2


def generate_normal_positive_and_negative_pairs(validate_set, positive_path, negative_path, number):
    validate_set = remove_project_key(validate_set)
    validate_source_function_keys = list(validate_set.keys())
    max_number = count_for_max_number(validate_set)
    print("maximum number of positive pairs: {}".format(str(max_number)))
    selected_positive_pairs = []
    selected_negative_pairs = []
    with tqdm(total=number) as pbar:
        while len(selected_positive_pairs) < number:
            while (1):
                source_function_key1, source_function_key2 = random.sample(validate_source_function_keys, k=2)
                f1 = random.sample(validate_set[source_function_key1]["equal"], k=1)[0]
                f2 = select_binary_function_in_same_compilation(f1, validate_set[source_function_key1]["partial"])
                if not f2:
                    continue
                f4 = random.sample(validate_set[source_function_key2]["partial"], k=1)[0]
                # if f4 not in validate_set[source_function_key1]["partial"] and \
                #         [f1, f2] not in selected_positive_pairs and [f1, f4] not in selected_negative_pairs:
                if f4 not in validate_set[source_function_key1]["partial"]:
                    break
            selected_positive_pairs.append([f1, f2])
            selected_negative_pairs.append([f1, f4])
            pbar.update()
    pbar.close()

    write_to_pairs_csv(positive_path, selected_positive_pairs)
    write_to_pairs_csv(negative_path, selected_negative_pairs)


def extract_bb_number_of_binary_function(flowchart_folder):
    binary_function_to_bb_num = {}
    binary_function_to_start_address = {}
    binary_address_to_func_name = {}
    with tqdm(total=len(os.listdir(flowchart_folder))) as pbar:
        for csv_file_name in os.listdir(flowchart_folder):
            csv_file_path = os.path.join(flowchart_folder, csv_file_name)
            csv_reader = csv.reader(open(csv_file_path, "r"))
            rows = [row for row in csv_reader]
            for line in rows[1:]:
                binary_name, function_address, bb_num = line[0], line[1], line[5]
                function_name = line[2]
                if binary_name not in binary_function_to_bb_num:
                    binary_function_to_bb_num[binary_name] = {}
                binary_function_to_bb_num[binary_name][function_address] = bb_num
                if binary_name not in binary_function_to_start_address:
                    binary_function_to_start_address[binary_name] = {}
                binary_function_to_start_address[binary_name][function_name] = function_address
                if binary_name not in binary_address_to_func_name:
                    binary_address_to_func_name[binary_name] = {}
                binary_address_to_func_name[binary_name][function_address] = function_name
            pbar.update()
        pbar.close()
    return binary_function_to_bb_num, binary_function_to_start_address, binary_address_to_func_name


def select_satisfied_functions(functions, binary_function_to_bb_num, binary_function_to_start_address):
    selected_functions = []
    for single_function in functions:
        binary_name, function_name = single_function
        try:
            function_address = binary_function_to_start_address[binary_name][function_name]
            bb_num = binary_function_to_bb_num[binary_name][function_address]
            if int(bb_num) >= 5:
                selected_functions.append(single_function)
        except:
            print(single_function)
            continue
    return selected_functions


def remove_short_binary_functions(inlined_function_mappings, binary_function_to_bb_num,
                                  binary_function_to_start_address):
    new_inlined_function_mappings = {}
    for project_name in inlined_function_mappings:
        new_inlined_function_mappings[project_name] = {}
        for source_function_key in inlined_function_mappings[project_name]:
            corresponding_functions = inlined_function_mappings[project_name][source_function_key]
            corresponding_functions = select_satisfied_functions(corresponding_functions, binary_function_to_bb_num,
                                                                 binary_function_to_start_address)
            if corresponding_functions:
                new_inlined_function_mappings[project_name][source_function_key] = \
                    corresponding_functions
    return new_inlined_function_mappings


def split_dataset_using_partition(acfg_disasm_folder, dest_split_fodler, inlined_function_mappings, project_partition):
    train_set_keys = project_partition["training"]
    test_set_keys = project_partition["testing"]
    validate_set_keys = project_partition["validation"]
    generate_split_dataset(acfg_disasm_folder, dest_split_fodler, train_set_keys, test_set_keys, validate_set_keys)
    train_set = extract_key_mapped_dicts(inlined_function_mappings, train_set_keys)
    test_set = extract_key_mapped_dicts(inlined_function_mappings, test_set_keys)
    validate_set = extract_key_mapped_dicts(inlined_function_mappings, validate_set_keys)
    return train_set, test_set, validate_set


def summary_all_binary_functions(binary_i64_to_function_mapping, binary_function_to_start_address):
    selected_dataset = {}
    for project_name in binary_i64_to_function_mapping:
        for binary_path in binary_i64_to_function_mapping[project_name]:
            binary_function_names = list(binary_i64_to_function_mapping[project_name][binary_path].keys())
            selected_dataset[binary_path] = []
            for binary_function_name in binary_function_names:
                try:
                    start_address = binary_function_to_start_address[binary_path][binary_function_name]
                    start_address_10 = int(start_address, 16)
                    selected_dataset[binary_path].append(start_address_10)
                except:
                    print("error: cannot found the start address of function {} in binary {}"
                          .format(binary_function_name, binary_path))
    return selected_dataset


def convert_function_name_to_address(inlined_function_mappings, binary_function_to_start_address):
    for project_name in inlined_function_mappings:
        for source_function_key in inlined_function_mappings[project_name]:
            binary_function_tuple_lists = inlined_function_mappings[project_name][source_function_key]
            binary_function_address_lists = []
            for binary_function_tuple in binary_function_tuple_lists:
                binary_path, function_name = binary_function_tuple
                binary_address = binary_function_to_start_address[binary_path][function_name]
                binary_function_address_lists.append([binary_path, binary_address])
            inlined_function_mappings[project_name][source_function_key] = binary_function_address_lists
    return inlined_function_mappings


def generate_ranking_positive_and_negative_pairs(test_set, testing_ranking_positive_path,
                                                 testing_ranking_negative_path, pos_number, neg_number):
    validate_set = remove_project_key(test_set)
    validate_source_function_keys = list(validate_set.keys())
    max_number = count_for_max_number(validate_set)
    print("maximum number of positive pairs: {}".format(str(max_number)))
    selected_positive_pairs = []
    selected_negative_pairs = []
    with tqdm(total=pos_number) as pbar:
        while len(selected_positive_pairs) < pos_number:
            while (1):
                source_function_key1 = random.sample(validate_source_function_keys, k=1)[0]
                f1 = random.sample(validate_set[source_function_key1]["equal"], k=1)[0]
                f2 = select_binary_function_in_same_compilation(f1, validate_set[source_function_key1]["partial"])
                if not f2:
                    continue
                if [f1, f2] not in selected_positive_pairs:
                    break
            selected_positive_pairs.append([f1, f2])
            pbar.update()
    pbar.close()

    with tqdm(total=neg_number) as pbar:
        while len(selected_negative_pairs) < neg_number:
            while (1):
                source_function_key1, source_function_key2 = random.sample(validate_source_function_keys, k=2)
                f1 = random.sample(validate_set[source_function_key1]["equal"], k=1)[0]
                f4 = random.sample(validate_set[source_function_key2]["partial"], k=1)[0]
                if f4 not in validate_set[source_function_key1]["partial"] and [f1, f4] not in selected_negative_pairs:
                    break
            selected_negative_pairs.append([f1, f4])
            pbar.update()
    pbar.close()

    write_to_pairs_csv(testing_ranking_positive_path, selected_positive_pairs)
    write_to_pairs_csv(testing_ranking_negative_path, selected_negative_pairs)


def summary_mapping_files(mapping_results_dir, binary_dir, source_prefix):
    binary_i64_to_function_mapping = {}
    for project_name in os.listdir(mapping_results_dir):
        print("    processing project {}".format(project_name))
        project_dir = os.path.join(mapping_results_dir, project_name)
        binary_i64_to_function_mapping[project_name] = {}
        for file_name in os.listdir(project_dir):
            if "_mips_" in file_name:
                continue
            if file_name.endswith("_function_mapping.json"):
                mapping_file_path = os.path.join(project_dir, file_name)
                mapping_file_content = read_json(mapping_file_path)
                project_function_mapping = \
                    get_binary_function_mapped_source_functions(mapping_file_content, source_prefix)
                binary_i64_name = file_name.replace("_function_mapping.json", ".i64")
                binary_i64 = os.path.join(binary_dir, project_name, binary_i64_name)
                binary_i64_to_function_mapping[project_name][binary_i64] = project_function_mapping
    return binary_i64_to_function_mapping


def get_source_function_mapped_inlining_functions(binary_i64_to_function_mapping):
    source_function_key_to_binary_functions = {}
    for project_name in binary_i64_to_function_mapping:
        print("    processing project {}".format(project_name))
        if project_name not in source_function_key_to_binary_functions:
            source_function_key_to_binary_functions[project_name] = {}
        project_binary_mappings = binary_i64_to_function_mapping[project_name]
        for binary_i64 in project_binary_mappings:
            BF_to_SF_mapping_dict = project_binary_mappings[binary_i64]
            for BF in BF_to_SF_mapping_dict:
                SF_list = BF_to_SF_mapping_dict[BF]
                if len(SF_list) == 1:
                    continue
                else:
                    # SF_list -> SF_list[1:] the original function should be removed
                    for SF in SF_list:
                        if SF not in source_function_key_to_binary_functions[project_name]:
                            source_function_key_to_binary_functions[project_name][SF] = \
                                {"equal": [], "partial": [[binary_i64, BF]]}
                        else:
                            if [binary_i64, BF] not in \
                                    source_function_key_to_binary_functions[project_name][SF]["partial"]:
                                source_function_key_to_binary_functions[project_name][SF]["partial"].append(
                                    [binary_i64, BF])
    return source_function_key_to_binary_functions


def convert_mapping_to_dict(inlined_function_mappings):
    inlined_function_dict = {}
    for project_name in inlined_function_mappings:
        inlined_function_dict[project_name] = {}
        project_mappings = inlined_function_mappings[project_name]
        for source_function_key in project_mappings:
            inlined_function_dict[project_name][source_function_key] = {}
            binary_function_lists = project_mappings[source_function_key]
            for binary_function in binary_function_lists:
                binary_name, function_address = binary_function
                inlined_function_dict[project_name][source_function_key][binary_name] = function_address
    return inlined_function_dict


def analyze_pattern_for_func_pair(BF_I_mapped_SF, BF_II_mapped_SFs, FCG_per_project, BF_II):
    if len(BF_II_mapped_SFs) == 1 and BF_II_mapped_SFs == [BF_I_mapped_SF]:
        return "equal"
    flag_one = False
    flag_two = False
    for B_SF in BF_II_mapped_SFs:
        if B_SF == BF_I_mapped_SF:
            continue
        if FCG_per_project.has_edge(B_SF, BF_I_mapped_SF):
            flag_one = True
        if FCG_per_project.has_edge(BF_I_mapped_SF, B_SF):
            flag_two = True
    if flag_one is False and flag_two is True:
        return "inline_other_functions"
    if flag_one is True and flag_two is False:
        return "direct_inline"
    if flag_one is True and flag_two is True:
        return "recursive_inline"
    if flag_one is False and flag_two is False:
        # BF_I_mapped_SF_successors = list(FCG_per_project.successors(BF_I_mapped_SF))
        # BF_I_mapped_SF_pres = list(FCG_per_project.predecessors(BF_I_mapped_SF))
        # error_cases.append([BF_I_mapped_SF, BF_II_mapped_SFs, BF_II])
        return "error"
    print("other situation")
    return "other_situation"


def add_func_to_dict(pattern1_mappings, project_name, sf, binary_func):
    if project_name not in pattern1_mappings:
        pattern1_mappings[project_name] = {}
    if sf not in pattern1_mappings[project_name]:
        pattern1_mappings[project_name][sf] = []
    pattern1_mappings[project_name][sf].append(binary_func)
    return pattern1_mappings


def classify_inlined_function_mappings(inlined_function_mappings, FCGs_of_all_projects,
                                       binary_address_to_func_name, dataset_1_mapping):
    pattern1_mappings = {}
    pattern2_mappings = {}
    pattern3_mappings = {}
    for project_name_version in FCGs_of_all_projects:
        print("processing project: {}".format(project_name_version))
        FCG_per_project = FCGs_of_all_projects[project_name_version]
        project_name = project_name_version.split("-")[0]
        if project_name == "libosip2":
            project_name = "osip"
        if project_name == "libidn2":
            project_name = "libidn"
        for sf in inlined_function_mappings[project_name]:
            binary_func_list = inlined_function_mappings[project_name][sf]
            strip_sf = "+".join(sf.split("+")[:-1])
            for binary_func in binary_func_list:
                binary_name, func_addr = binary_func
                func_name = binary_address_to_func_name[binary_name][func_addr]
                bf_mapped_sfs = dataset_1_mapping[project_name][binary_name][func_name]
                bf_mapped_sfs = ["+".join(sf.split("+")[:-1]) for sf in bf_mapped_sfs]
                inlining_pattern = analyze_pattern_for_func_pair(strip_sf, bf_mapped_sfs, FCG_per_project, binary_func)
                if inlining_pattern == "direct_inline":
                    pattern1_mappings = add_func_to_dict(pattern1_mappings, project_name, sf, binary_func)
                elif inlining_pattern == "inline_other_functions":
                    pattern2_mappings = add_func_to_dict(pattern2_mappings, project_name, sf, binary_func)
                elif inlining_pattern == "recursive_inline":
                    pattern3_mappings = add_func_to_dict(pattern3_mappings, project_name, sf, binary_func)
    return pattern1_mappings, pattern2_mappings, pattern3_mappings


def preprocessing_for_dataset_I():
    dataset_1_mapping_file = "dataset_1_mapping.json"
    if not os.path.exists(dataset_1_mapping_file):
        print("summary function mapping...")
        mapping_results_dir = "/path/to/binary2binary/dataset_I/mapping_results/"
        binary_dir = "IDBs/Dataset-1/"
        source_prefix = "/path/to/binary2binary/dataset_I/source/"
        dataset_1_mapping = summary_mapping_files(mapping_results_dir, binary_dir, source_prefix)
        write_json(dataset_1_mapping_file, dataset_1_mapping)
    else:
        dataset_1_mapping = read_json(dataset_1_mapping_file)

    source_function_key_to_binary_functions_file = "dataset_1_sf_to_bf.json"
    if not os.path.exists(source_function_key_to_binary_functions_file):
        print("get source function mapped binary functions")
        dataset_1_sf_to_bf = \
            get_source_function_mapped_inlining_functions(dataset_1_mapping)
        write_json(source_function_key_to_binary_functions_file, dataset_1_sf_to_bf)
    else:
        dataset_1_sf_to_bf = read_json(source_function_key_to_binary_functions_file)

    binary_function_to_bb_num_file_name = "dataset_1_binary_function_to_bb_num.json"
    binary_function_to_start_address_file = "dataset_1_binary_function_to_start_address.json"
    binary_address_to_func_name_file = "dataset_1_binary_address_to_func_name.json"
    if os.path.exists(binary_function_to_bb_num_file_name) is False or \
            os.path.exists(binary_function_to_start_address_file) is False or \
            os.path.exists(binary_address_to_func_name_file) is False:
        print("summary basic block numbers for binary functions")
        flowchart_folder = "/path/to/binary2binary/IDA_scripts/IDA_flowchart/flowchart_csv_dataset_I"
        binary_function_to_bb_num, binary_function_to_start_address, binary_address_to_func_name = \
            extract_bb_number_of_binary_function(flowchart_folder)
        write_json(binary_function_to_bb_num_file_name, binary_function_to_bb_num)
        write_json(binary_function_to_start_address_file, binary_function_to_start_address)
        write_json(binary_address_to_func_name_file, binary_address_to_func_name)
    else:
        binary_function_to_bb_num = read_json(binary_function_to_bb_num_file_name)
        binary_function_to_start_address = read_json(binary_function_to_start_address_file)
        binary_address_to_func_name = read_json(binary_address_to_func_name_file)

    inlined_function_mappings_file = "dataset_1_inlined_function_mappings.json"
    if os.path.exists(inlined_function_mappings_file) is False:
        inlined_function_mappings = extract_inlined_function_mapping(dataset_1_sf_to_bf)
        inlined_function_mappings = \
            remove_short_binary_functions(inlined_function_mappings, binary_function_to_bb_num,
                                          binary_function_to_start_address)
        inlined_function_mappings = convert_function_name_to_address(inlined_function_mappings,
                                                                     binary_function_to_start_address)
        write_json(inlined_function_mappings_file, inlined_function_mappings)
    else:
        inlined_function_mappings = read_json(inlined_function_mappings_file)

    pattern1_mapping_file = "pattern1_mapping.json"
    pattern2_mapping_file = "pattern2_mapping.json"
    pattern3_mapping_file = "pattern3_mapping.json"
    if os.path.exists(pattern1_mapping_file) is False or os.path.exists(
            pattern2_mapping_file) is False or os.path.exists(pattern3_mapping_file) is False:
        FCGs_of_all_projects_pickle_file = "source_fcgs.pkl"
        FCGs_of_all_projects = read_pickle(FCGs_of_all_projects_pickle_file)
        pattern1_mappings, pattern2_mappings, pattern3_mappings = \
            classify_inlined_function_mappings(inlined_function_mappings, FCGs_of_all_projects,
                                               binary_address_to_func_name, dataset_1_mapping)
        write_json(pattern1_mapping_file, pattern1_mappings)
        write_json(pattern2_mapping_file, pattern2_mappings)
        write_json(pattern3_mapping_file, pattern3_mappings)
    else:
        pattern1_mappings = read_json(pattern1_mapping_file)
        pattern2_mappings = read_json(pattern2_mapping_file)
        pattern3_mappings = read_json(pattern3_mapping_file)
    return pattern1_mappings, pattern2_mappings, pattern3_mappings


def extract_normal_function_mapping(source_function_key_to_binary_functions):
    normal_function_mappings = {}
    for project_name in source_function_key_to_binary_functions:
        project_mappings = source_function_key_to_binary_functions[project_name]
        for source_function_key in project_mappings:
            if project_mappings[source_function_key]["equal"]:
                if project_name not in normal_function_mappings:
                    normal_function_mappings[project_name] = {}
                normal_function_mappings[project_name][source_function_key] = \
                    project_mappings[source_function_key]["equal"]
    return normal_function_mappings


def proprecessing_for_dataset_II():
    dataset_2_mapping_file = "dataset_2_mapping.json"
    if not os.path.exists(dataset_2_mapping_file):
        print("summary function mapping...")
        mapping_results_dir = "/path/to/binary2binary/dataset_II/mapping_results/"
        binary_dir = "IDBs/Dataset-2/"
        source_prefix = "/path/to/binary2binary/dataset_II/source/"
        dataset_2_mapping = summary_mapping_files(mapping_results_dir, binary_dir, source_prefix)
        write_json(dataset_2_mapping_file, dataset_2_mapping)
    else:
        dataset_2_mapping = read_json(dataset_2_mapping_file)

    source_function_key_to_binary_functions_file = "dataset_2_sf_to_bf.json"
    if not os.path.exists(source_function_key_to_binary_functions_file):
        print("get source function mapped binary functions")
        dataset_2_sf_to_bf = \
            get_source_function_mapped_normal_functions(dataset_2_mapping)
        write_json(source_function_key_to_binary_functions_file, dataset_2_sf_to_bf)
    else:
        dataset_2_sf_to_bf = read_json(source_function_key_to_binary_functions_file)

    binary_function_to_bb_num_file_name = "dataset_2_binary_function_to_bb_num.json"
    binary_function_to_start_address_file = "dataset_2_binary_function_to_start_address.json"
    if os.path.exists(binary_function_to_bb_num_file_name) is False or \
            os.path.exists(binary_function_to_start_address_file) is False:
        print("summary basic block numbers for binary functions")
        flowchart_folder = "/path/to/binary2binary/IDA_scripts/IDA_flowchart/flowchart_csv_dataset_II"
        binary_function_to_bb_num, binary_function_to_start_address, _ = extract_bb_number_of_binary_function(
            flowchart_folder)
        write_json(binary_function_to_bb_num_file_name, binary_function_to_bb_num)
        write_json(binary_function_to_start_address_file, binary_function_to_start_address)
    else:
        binary_function_to_bb_num = read_json(binary_function_to_bb_num_file_name)
        binary_function_to_start_address = read_json(binary_function_to_start_address_file)

    normal_function_mappings_file = "dataset_2_normal_function_mappings.json"
    if os.path.exists(normal_function_mappings_file) is False:
        normal_function_mappings = extract_normal_function_mapping(dataset_2_sf_to_bf)
        normal_function_mappings = \
            remove_short_binary_functions(normal_function_mappings, binary_function_to_bb_num,
                                          binary_function_to_start_address)
        normal_function_mappings = convert_function_name_to_address(normal_function_mappings,
                                                                    binary_function_to_start_address)
        write_json(normal_function_mappings_file, normal_function_mappings)
    else:
        normal_function_mappings = read_json(normal_function_mappings_file)

    return normal_function_mappings


def summary_cross_inlining_mappings(dataset_2_normal_function_mappings, dataset_1_inlined_function_mappings, pattern_name):
    print("generate cross inlining mappings")
    cross_inlining_mappings_file = pattern_name + "cross_inlining_mappings.json"
    cross_inlining_mappings = {}
    for project_name in dataset_2_normal_function_mappings:
        if project_name not in dataset_1_inlined_function_mappings:
            continue
        cross_inlining_mappings[project_name] = {}
        for source_function_key in dataset_2_normal_function_mappings[project_name]:
            if source_function_key not in dataset_1_inlined_function_mappings[project_name]:
                continue
            cross_inlining_mappings[project_name][source_function_key] = \
                {"equal": dataset_2_normal_function_mappings[project_name][source_function_key],
                 "partial": dataset_1_inlined_function_mappings[project_name][source_function_key]}
    write_json(cross_inlining_mappings_file, cross_inlining_mappings)
    return cross_inlining_mappings


def read_dataset_using_partition(inlined_function_mappings, project_partition):
    train_set_keys = project_partition["training"]
    test_set_keys = project_partition["testing"]
    validate_set_keys = project_partition["validation"]
    train_set = extract_key_mapped_dicts(inlined_function_mappings, train_set_keys)
    test_set = extract_key_mapped_dicts(inlined_function_mappings, test_set_keys)
    validate_set = extract_key_mapped_dicts(inlined_function_mappings, validate_set_keys)
    return train_set, test_set, validate_set


def generate_training_datasets(cross_inlining_mappings, pattern_name):
    project_partition_file = "project_partition.json"
    dataset_partition_folder = "split_dataset"
    dest_split_fodler = "/path/to/binary2binary/DBs/Dataset-1/features"

    acfg_disasm_folder = "/path/to/binary2binary/IDA_scripts/IDA_acfg_disasm/acfg_disasm_Dataset-1"
    if os.path.exists(dataset_partition_folder) is True:
        project_partition = read_json(project_partition_file)
        train_set, test_set, validate_set = \
            read_dataset_using_partition(cross_inlining_mappings, project_partition)
        if os.path.exists(dataset_partition_folder) is False:
            os.mkdir(dataset_partition_folder)
        write_json(os.path.join(dataset_partition_folder, pattern_name + "train_set_mapping.json"), train_set)
        write_json(os.path.join(dataset_partition_folder, pattern_name + "test_set_mapping.json"), test_set)
        write_json(os.path.join(dataset_partition_folder, pattern_name + "validate_set_mapping.json"), validate_set)
    else:
        project_partition = read_json(project_partition_file)
        train_set, test_set, validate_set = \
            split_dataset_using_partition(acfg_disasm_folder, dest_split_fodler, cross_inlining_mappings,
                                          project_partition)
        if os.path.exists(dataset_partition_folder) is False:
            os.mkdir(dataset_partition_folder)
        write_json(os.path.join(dataset_partition_folder, pattern_name + "train_set_mapping.json"), train_set)
        write_json(os.path.join(dataset_partition_folder, pattern_name + "test_set_mapping.json"), test_set)
        write_json(os.path.join(dataset_partition_folder, pattern_name + "validate_set_mapping.json"), validate_set)
    return validate_set, test_set


def generate_testing_datasets(validate_set, test_set, pattern_name):
    print("generating validation positive and negative pairs")
    validation_pairs_folder = "/path/to/binary2binary/DBs/Dataset-1+2/pairs/validation"
    if os.path.exists(validation_pairs_folder) is False:
        os.makedirs(validation_pairs_folder)
    validation_positive_path = os.path.join(validation_pairs_folder, pattern_name + "pos_validation_Dataset-1.csv")
    validation_negative_path = os.path.join(validation_pairs_folder, pattern_name + "neg_validation_Dataset-1.csv")
    if not (os.path.exists(validation_positive_path) and os.path.exists(validation_negative_path)):
        generate_normal_positive_and_negative_pairs(validate_set,
                                                    validation_positive_path,
                                                    validation_negative_path, number=40000)

    print("generating testing positive and negative pairs")
    test_pairs_folder = "/path/to/binary2binary/DBs/Dataset-1+2/pairs/testing"
    if os.path.exists(test_pairs_folder) is False:
        os.makedirs(test_pairs_folder)
    testing_positive_path = os.path.join(test_pairs_folder, pattern_name + "pos_testing_Dataset-1.csv")
    testing_negative_path = os.path.join(test_pairs_folder, pattern_name + "neg_testing_Dataset-1.csv")
    if not (os.path.exists(testing_positive_path) and os.path.exists(testing_negative_path)):
        generate_normal_positive_and_negative_pairs(test_set, testing_positive_path,
                                                    testing_negative_path, number=40000)
    testing_ranking_positive_path = os.path.join(test_pairs_folder, pattern_name + "pos_rank_testing_Dataset-1.csv")
    testing_ranking_negative_path = os.path.join(test_pairs_folder, pattern_name + "neg_rank_testing_Dataset-1.csv")
    if not (os.path.exists(testing_ranking_positive_path) and os.path.exists(testing_ranking_negative_path)):
        generate_ranking_positive_and_negative_pairs(test_set, testing_ranking_positive_path,
                                                     testing_ranking_negative_path, pos_number=800, neg_number=80000)


def main():
    dataset_2_normal_function_mappings = proprecessing_for_dataset_II()
    pattern1_mappings, pattern2_mappings, pattern3_mappings = preprocessing_for_dataset_I()
    for mappings, pattern_name in [(pattern1_mappings, "pattern1_"),
                                   (pattern2_mappings, "pattern2_"),
                                   (pattern3_mappings, "pattern3_")]:
        cross_inlining_mappings = \
            summary_cross_inlining_mappings(dataset_2_normal_function_mappings, mappings, pattern_name)

        validate_set, test_set = generate_training_datasets(cross_inlining_mappings, pattern_name)

        generate_testing_datasets(validate_set, test_set, pattern_name)


if __name__ == "__main__":
    main()
