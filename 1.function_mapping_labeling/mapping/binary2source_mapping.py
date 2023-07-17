# new version of binary2source mapping:
# using understands to obtain the source line -- source entities mapping
# using IDA Pro to disassemble
# using readelf to get the line number mapping information
# using understand to get the source level depends


import csv
import os
import pickle
import re
import json
import platform

if platform.system().lower() == 'windows':
    platform_separator = "\\"
    substitute_separator = "/"
elif platform.system().lower() == 'linux':
    platform_separator = "/"
    substitute_separator = "\\"


def read_pickle(ghi_file):
    with open(ghi_file, "rb") as f:
        ghi_content = pickle.load(f)
    return ghi_content


def read_file(path):
    file_content = open(path, "r")
    file_lines = file_content.readlines()
    file_content.close()
    return file_lines


def cal_lcs_sim(first_str, second_str):
    len_1 = len(first_str.strip())
    len_2 = len(second_str.strip())
    max_len = max(len_1, len_2) + 1
    len_vv = [[0] * max_len] * max_len

    for i in range(1, len_1 + 1):
        for j in range(1, len_2 + 1):
            if first_str[i - 1] == second_str[j - 1]:
                len_vv[i][j] = 1 + len_vv[i - 1][j - 1]
            else:
                len_vv[i][j] = max(len_vv[i - 1][j], len_vv[i][j - 1])

    return float(float(len_vv[len_1][len_2] * 2) / float(len_1))


def get_the_most_similar_one(matched_source_paths, source_file_relative_path):
    similarities = []
    for matched_path in matched_source_paths:
        similarity = cal_lcs_sim(source_file_relative_path, matched_path)
        similarities.append(similarity)
    max_index = similarities.index(max(similarities))
    return matched_source_paths[max_index]


def search_path_with_suffix(source_file_relative_path, paths):
    source_file_name = source_file_relative_path.split("/")[-1]
    matched_source_paths = []
    for i in range(len(paths) - 1, -1, -1):
        if paths[i].split(platform_separator)[-1] == source_file_name:
            matched_source_paths.append(paths[i])
    if len(matched_source_paths) == 1:
        return matched_source_paths[0]
    elif len(matched_source_paths) == 0:
        return None
    elif len(matched_source_paths) >= 1:
        # print("matching more than one candicates paths!")
        source_file_relative_path = platform_separator.join(source_file_relative_path.split("/"))
        most_similar_path = get_the_most_similar_one(matched_source_paths, source_file_relative_path)
        return most_similar_path


def search_path(file_name, paths):
    for i in range(len(paths) - 1, -1, -1):
        if file_name in paths[i]:
            return paths[i]
    return file_name


def extract_line_mapping(mapping_file_content):
    """processing line mapping file"""
    mapping_relation = []
    i = 0
    # paths = []
    while i < len(mapping_file_content):
        new_content = mapping_file_content[i].strip("\n").strip(" ").split()

        if len(new_content) == 1 or len(new_content) == 2 and new_content[0] == "CU:":

            # paths.append(new_content[-1])
            i = i + 1
            if re.match("File name  ", mapping_file_content[i]):
                i = i + 1
            if i >= len(mapping_file_content):
                break
            new_content = mapping_file_content[i].strip("\n").strip(" ").split()
            while i < len(mapping_file_content) and \
                (len(new_content) == 3 or len(new_content) == 0 or len(new_content) == 4):
                if len(new_content) == 0:
                    i = i + 1
                    if i >= len(mapping_file_content):
                        break
                    new_content = mapping_file_content[i].strip("\n").strip(" ").split()
                    continue
                # path = search_path(new_content[0], paths)
                # new_content[0] = path
                # if path.endswith("[++]"):
                #     new_content[0] = "./lib" + path.replace("[++]", "")[1:]
                # new_content[-1] = new_content[-1].replace("[0]", "")
                # new_content = mapping_file_content[i].strip("\n").strip(" ").split()
                if new_content[1] == "0":
                    i = i + 1
                    if i >= len(mapping_file_content):
                        break
                    new_content = mapping_file_content[i].strip("\n").strip(" ").split()
                    continue
                if len(new_content) == 4:
                    new_content = new_content[:3]
                mapping_relation.append(new_content)
                i = i + 1
                new_content = mapping_file_content[i].strip("\n").strip(" ").split()
        else:
            i = i + 1

    return mapping_relation


def convert_to_dict(binary_function_range):
    """get address--> function dict"""
    address_function_dict = {}
    for binary_function in binary_function_range:
        start_address, end_address = binary_function_range[binary_function]
        start_address = int(start_address, 16)
        end_address = int(end_address, 16)
        for i in range(start_address + 1, end_address):
            current_address = hex(i)
            address_function_dict[current_address] = binary_function
    return address_function_dict


def add_binary_function_info(address_function_dict, mapping_relation):
    """add binary function info"""
    source2binary_mapping = []
    source2binary_mapping_detail = []
    for file_line_address in mapping_relation:
        address = file_line_address[-1]
        try:
            binary_function = address_function_dict[address]
        except:
            continue
        file_line_binaryfunc = [file_line_address[0], file_line_address[1], binary_function]
        file_line_binary_func_address = [file_line_address[0], file_line_address[1], binary_function, address]
        source2binary_mapping.append(file_line_binaryfunc)
        source2binary_mapping_detail.append(file_line_binary_func_address)
    return source2binary_mapping, source2binary_mapping_detail


def get_line_number_refer_entity(project_dir, line_number, source_file_path, source_entities):
    """get source function corresponding to the line"""
    # file_entities = {}
    try:
        file_entities = source_entities[source_file_path]
    except:
        return None, None
    if not file_entities:
        # print("did not find functions of this file")
        return None, None
    for entity in file_entities:
        # print(source_file_path, entity)
        entity_info_struct = file_entities[entity]
        if type(entity_info_struct) is dict:
            entity_start_line = int(file_entities[entity]["start_point"][0]) + 1
            entity_end_line = int(file_entities[entity]["end_point"][0]) + 1
            if entity_start_line <= int(line_number) <= entity_end_line:
                return entity, (entity_start_line, entity_end_line)
        if type(entity_info_struct) is list:
            for entity_dict in entity_info_struct:
                entity_start_line = int(entity_dict["start_point"][0]) + 1
                entity_end_line = int(entity_dict["end_point"][0]) + 1
                if entity_start_line <= int(line_number) <= entity_end_line:
                    return entity, (entity_start_line, entity_end_line)

    return None, None


def convert_to_absolute_path(project_dir, source_file_relative_path, c_file_path_list):
    """
    convert the relative path in debug results to the absolute path of source files
    """
    # if source_file_relative_path.startswith("./"):
    #     source_file_relative_path.replace("./", "gnulib/")
    # if source_file_relative_path.startswith("./"):
    #     source_file_relative_path = source_file_relative_path[2:]
    guess_source_file_path = os.path.join(os.path.join(project_dir, "src"), source_file_relative_path)
    if os.path.exists(guess_source_file_path):
        return guess_source_file_path
    guess_source_file_path = os.path.join(os.path.join(project_dir, "lib"), source_file_relative_path)
    if os.path.exists(guess_source_file_path):
        return guess_source_file_path
    source_file_path = os.path.join(project_dir, source_file_relative_path.replace("/", platform_separator))
    # print(source_file_path)

    if os.path.exists(source_file_path) is False:
        source_file_path = search_path_with_suffix(source_file_relative_path, c_file_path_list)
    return source_file_path


def get_longest_common_prefix(li):
    result = ''
    for i in zip(*li):
        if len(set(i)) == 1:
            result += i[0]
        else:
            break
    return result


def get_common_dir(source_entities):
    file_paths = list(source_entities.keys())
    longest_common_prefix = get_longest_common_prefix(file_paths)
    return longest_common_prefix


def convert_source_entities(source_entities):
    source_file_line_to_function = {}
    for file_path in source_entities:
        source_file_line_to_function[file_path] = {}
        function_dict = source_entities[file_path]
        for function_name in function_dict:
            single_function_info = function_dict[function_name]
            if type(single_function_info) is dict:
                start_point = single_function_info["start_point"]
                end_point = single_function_info["end_point"]
                start_line = start_point[0] + 1
                end_line = end_point[0] + 1
                for line in range(start_line, end_line + 1):
                    source_file_line_to_function[file_path][line] = function_name
            elif type(single_function_info) is list:
                for sub_function_info in single_function_info:
                    start_point = sub_function_info["start_point"]
                    end_point = sub_function_info["end_point"]
                    start_line = start_point[0] + 1
                    end_line = end_point[0] + 1
                    for line in range(start_line, end_line + 1):
                        source_file_line_to_function[file_path][line] = function_name
    return source_file_line_to_function


def get_line_number_refer_entity_by_dict(line_number, source_file_path, source_file_line_to_function, source_entities):
    try:
        function_name = source_file_line_to_function[source_file_path][line_number]
        function_info = source_entities[source_file_path][function_name]
        if type(function_info) is dict:
            entity_start_line = function_info["start_point"][0] + 1
            entity_end_line = function_info["end_point"][0] + 1
        elif type(function_info) is list:
            for sub_function_info in function_info:
                entity_start_line = sub_function_info["start_point"][0] + 1
                entity_end_line = sub_function_info["end_point"][0] + 1
                if entity_start_line <= line_number <= entity_end_line:
                    break
        return function_name, (entity_start_line, entity_end_line)
    except:
        return None, None


def add_source_function_information(source2binary_mapping_detail, source_entities, c_file_path_list):
    """ add function belonging information to source2binary mapping for further analysis"""
    source_file_list = []
    source_relative_path_to_absolute_path = {}
    project_dir = get_common_dir(source_entities)
    source_file_line_to_function = convert_source_entities(source_entities)
    for line in source2binary_mapping_detail:
        source_file_relative_path = line[0]
        # if source_file_relative_path.endswith(".y:"):
        #     source_file_relative_path = source_file_relative_path[:-1]
        if source_file_relative_path not in source_relative_path_to_absolute_path:
            source_file_path = convert_to_absolute_path(project_dir, source_file_relative_path, c_file_path_list)
            source_relative_path_to_absolute_path[source_file_relative_path] = source_file_path
        else:
            source_file_path = source_relative_path_to_absolute_path[source_file_relative_path]
        if not source_file_path or os.path.exists(source_file_path) is False:
            line.insert(2, None)
            line.insert(3, None)
            continue
        line[0] = source_file_path
        line_number = line[1]
        if line_number == "0":
            line.insert(2, None)
            line.insert(3, None)
            continue
        line_number_refer_entity, entity_range = get_line_number_refer_entity_by_dict(int(line_number),
                                                                                      source_file_path,
                                                                                      source_file_line_to_function,
                                                                                      source_entities)
        if line_number_refer_entity:
            line.insert(2, line_number_refer_entity)
            line.insert(3, entity_range)
        else:
            # if not source_file_path.endswith(".y"):
            #     print("warning: there may be error when parsing file {}".format(source_file_path))
            line.insert(2, None)
            line.insert(3, None)
    return source2binary_mapping_detail


def counting_address_coverage(Function_addresses, mapping_relation):
    """
    counting to what extent the mapping file can cover the content of assembly
    """
    binary_assembly_address = []
    binary_mapping_address = []
    for function_address in Function_addresses:
        binary_assembly_address = binary_assembly_address + function_address
    for mapping_line in mapping_relation:
        binary_mapping_address.append(mapping_line[-1])

    print(len(binary_mapping_address))
    print(len(binary_assembly_address))
    print(len(set(binary_mapping_address).intersection(set(binary_assembly_address))))


def read_range_file_csv(binary_range_file):
    binary_range = {}
    csv_reader = csv.DictReader(open(binary_range_file, "r"))
    rows = [row for row in csv_reader]
    for line in rows:
        try:
            function_address = line["fva"]
            function_name = line["func_name"]
            start_address, end_address = line["start_ea"], line["end_ea"]
            binary_range[function_name] = [start_address, end_address]
        except:
            print(line)
            raise Exception
    return binary_range


def remove_conflict_mapping(mapping_relation):
    address_to_source_line_dict = {}
    conflict_address = []
    for mapping_line in mapping_relation:
        try:
            source_file, source_line, address = mapping_line
        except:
            print(mapping_line)
        if address not in address_to_source_line_dict:
            address_to_source_line_dict[address] = source_file + source_line
        else:
            if source_file + source_line != address_to_source_line_dict[address]:
                conflict_address.append(address)
    new_mapping_relations = []
    for mapping_line in mapping_relation:
        address = mapping_line[2]
        if address in conflict_address:
            continue
        else:
            new_mapping_relations.append(mapping_line)
    return new_mapping_relations


def extract_entity_mapping(binary_range_file, source_entities_info, debug_file, c_file_path_list):
    """
    analyze every binary file about its mapping information
    """

    binary_function_range = read_range_file_csv(binary_range_file)

    address_function_dict = convert_to_dict(binary_function_range)

    mapping_file_content = read_file(debug_file)
    mapping_relation = extract_line_mapping(mapping_file_content)
    # print(mapping_relation)
    # mapping_relation = remove_conflict_mapping(mapping_relation)
    # counting the percentage of mapping address in assembly address
    # counting_address_coverage(Function_addresses, mapping_relation)

    source2binary_mapping, source2binary_mapping_detail = \
        add_binary_function_info(address_function_dict, mapping_relation)
    # source_line_binary_function_reference = get_source_line_reference(source2binary_mapping)
    # source_line_function, source_function_binary_function = \
    #     get_function_of_source_line(source_line_binary_function_reference)
    source2binary_mapping_full = add_source_function_information(source2binary_mapping_detail,
                                                                 source_entities_info, c_file_path_list)
    # print(source2binary_mapping_full)
    return source2binary_mapping_full


def get_binary2source_entity_mapping(source2binary_mapping_full):
    """ for each binary functions, aggregate all source functions mapping to this function"""
    binary2source_function_mapping = {}
    for mapping_line in source2binary_mapping_full:

        if mapping_line[-2] not in binary2source_function_mapping:
            binary2source_function_mapping[mapping_line[-2]] = []

        if mapping_line[1] == "0":
            continue

        if [mapping_line[0], mapping_line[2], mapping_line[3]] not in binary2source_function_mapping[mapping_line[-2]]:
            if mapping_line[3]:
                binary2source_function_mapping[mapping_line[-2]].append(
                    [mapping_line[0], mapping_line[2], mapping_line[3]])

    return binary2source_function_mapping


def write_json_file(file_name, file_content):
    """write dict to json file"""
    with open(file_name, "w") as f:
        json_str = json.dumps(file_content)
        f.write(json_str)


def find_main_source_function(correct_entity_group, binary_function):
    """try to find the main function that get other functions inlined"""
    for source_entity in correct_entity_group:
        if source_entity[1] == binary_function:
            return source_entity
    return None


def simply_source_entity(source_entity_groups):
    """for all groups, if cannot find the entity, add it to un_correct
                        if can, remove its line information and add to correct"""
    correct_entity_group = []
    un_correct_entity_group = []
    for source_entity in source_entity_groups:
        if source_entity[2] is None:
            un_correct_entity_group.append(source_entity)
        else:
            if [source_entity[0], source_entity[2]] not in correct_entity_group:
                correct_entity_group.append([source_entity[0], source_entity[2]])
    return correct_entity_group, un_correct_entity_group


def merge_dependence(source_dependence, add_dependence):
    source_function_added = []
    for add_dependence_line in add_dependence:
        if add_dependence_line[:2] not in source_dependence:
            source_function_added.append(add_dependence_line[:2])
            source_dependence.append(add_dependence_line[:2])
    return source_dependence, source_function_added


def extract_source_dependence(source_entities_info, main_source_function):
    """extract source dependence of a source file"""
    global call_depth
    source_dependence = []
    source_function_to_be_analyzed = [main_source_function]
    for i in range(call_depth):
        source_function_added_list = []
        for function in source_function_to_be_analyzed:
            if function[0] not in source_entities_info or function[1] not in source_entities_info[function[0]]:
                continue
            source_function_info = source_entities_info[function[0]][function[1]]
            source_dependence, source_function_added = merge_dependence(source_dependence, source_function_info["use"])
            source_function_added_list = source_function_added_list + source_function_added
        source_function_to_be_analyzed = source_function_added_list
    return source_dependence


def get_contain_flag(correct_entity_group, source_dependence):
    """determine whether correct_entity_group is included in source_dependence"""
    contain_flag = True
    for inline_entity in correct_entity_group:
        if inline_entity not in source_dependence:
            contain_flag = False
            break
    return contain_flag


def reasoning_binary2source_mapping_from_source_entity_dependence_test(binary2source_file_entity_mapping_dict,
                                                                       source_entities_info):
    """reasoning how inline occur in binary and from source dependence to predict function inline"""
    contain_results = {}
    binary_function_with_main_function_num = 0

    binary_function_without_main_function = {}
    binary_function_without_main_function_num = 0

    unresolved_entity = {}
    true_num = 0
    false_num = 0
    for binary in binary2source_file_entity_mapping_dict:
        contain_results[binary] = {}
        unresolved_entity[binary] = {}
        binary_function_without_main_function[binary] = {}
        binary_function_groups = binary2source_file_entity_mapping_dict[binary]
        for binary_function in binary_function_groups:
            source_entity_groups = binary_function_groups[binary_function]

            # leave the case which function cannot be found and record them
            correct_entity_group, un_correct_entity_group = simply_source_entity(source_entity_groups)
            unresolved_entity[binary] = un_correct_entity_group

            main_source_function = find_main_source_function(correct_entity_group, binary_function)

            #  deal with the situation which the main function exist
            if main_source_function:
                binary_function_with_main_function_num += 1
                correct_entity_group.remove(main_source_function)
                source_dependence = extract_source_dependence(source_entities_info, main_source_function)
                contain_flag = get_contain_flag(correct_entity_group, source_dependence)
                contain_results[binary][binary_function] = contain_flag
                if contain_flag:
                    true_num += 1
                else:
                    false_num += 1
            # record the case which main function doesn't exist
            else:
                binary_function_without_main_function_num += 1
                binary_function_without_main_function[binary][binary_function] = source_entity_groups
    return contain_results, true_num, false_num, binary_function_without_main_function, unresolved_entity, \
           binary_function_with_main_function_num, binary_function_without_main_function_num


def count_ratio_of_function_inline(binary2source_entity_mapping_simple_dict):
    """ratios = functions that occurred inline / all functions"""
    inline_function_num = 0
    no_inline_function_num = 0
    for binary in binary2source_entity_mapping_simple_dict:
        for binary_function in binary2source_entity_mapping_simple_dict[binary]:
            source_functions = binary2source_entity_mapping_simple_dict[binary][binary_function]
            if len(source_functions) > 1:
                inline_function_num += 1
            else:
                no_inline_function_num += 1

    print(inline_function_num)
    print(no_inline_function_num)


def write_csv_for_reasoning(record_result_on_call_graph_csv, record_result_on_call_graph):
    csv_writer = csv.writer(open(record_result_on_call_graph_csv, "w", newline=""))
    write_first_line = True
    for call_depth_ in record_result_on_call_graph:
        if write_first_line:
            csv_writer.writerow(["call_depth", "without main", "with main", "right reasoned", "false reasoned"])
            write_first_line = False
        line_items = []
        for key in record_result_on_call_graph[call_depth_]:
            line_items.append(record_result_on_call_graph[call_depth_][key])
        csv_writer.writerow([call_depth_] + line_items)
