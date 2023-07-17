import os


import os
import json
from tree_sitter import Language, Parser


def read_c_files(coreutils_path, C_files_list):
    c_file_path_list = []
    g = os.walk(coreutils_path)
    for path, dir_list, file_list in g:
        for file_name in file_list:
            if file_name.endswith(C_files_list):
                c_file_path = os.path.join(path, file_name)
                c_file_path_list.append(c_file_path)

    return c_file_path_list


def read_file(c_file_path):
    with open(c_file_path, "r", encoding="ISO-8859-1") as f:
        file_content = f.read()
        return file_content


def traverse_tree_to_leaf(tree):
    cursor = tree.walk()

    reached_root = False
    while reached_root == False:

        if cursor.goto_first_child():
            continue
        else:
            if cursor.node.type != "comment":
                yield True, cursor.node
            else:
                yield False, cursor.node

        if cursor.goto_next_sibling():
            continue

        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True

            if cursor.goto_next_sibling():
                retracing = False


def traverse_tree_with_depth(tree, depth=1):
    cursor = tree.walk()

    reached_root = False
    while reached_root == False:
        yield cursor.node, depth

        if cursor.goto_first_child():
            depth += 1
            continue

        if cursor.goto_next_sibling():
            continue

        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True
            else:
                depth -= 1

            if cursor.goto_next_sibling():
                retracing = False


def traverse_tree(tree):
    cursor = tree.walk()

    reached_root = False
    while reached_root == False:
        yield cursor.node

        if cursor.goto_first_child():
            continue

        if cursor.goto_next_sibling():
            continue

        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True

            if cursor.goto_next_sibling():
                retracing = False


def get_file_content_by_point(file_content_by_lines, start_point, end_point):
    content = []
    start_line = start_point[0]
    start_column = start_point[1]
    end_line = end_point[0]
    end_column = end_point[1]
    for line in range(start_line, end_line + 1):
        if line == start_line and line == end_line:
            content.append(file_content_by_lines[line][start_column:end_column])
        elif line == start_line:
            content.append(file_content_by_lines[line][start_column:])
        elif line == end_line:
            content.append(file_content_by_lines[line][:end_column])
        else:
            content.append(file_content_by_lines[line])
    return "\n".join(content)


def get_node_content(sub_child, file_content):
    start_byte = sub_child.start_byte
    end_byte = sub_child.end_byte
    function_name_by_byte = bytes(file_content, "utf8")[int(start_byte): int(end_byte)]
    function_name_by_byte = str(function_name_by_byte, "utf-8")
    start_point = sub_child.start_point
    end_point = sub_child.end_point
    file_content_by_lines = file_content.split("\n")
    function_name_by_point = get_file_content_by_point(file_content_by_lines, start_point, end_point)
    # if function_name_by_byte != function_name_by_point:
    #     print("??")
    return function_name_by_point


def find_function_name_normal(node, file_content):
    function_name = ""
    for child in traverse_tree(node):
        if child.type == "function_declarator":
            sub_children = child.children
            for sub_child in sub_children:
                if sub_child.type == "identifier":
                    function_name = get_node_content(sub_child, file_content)
                    return function_name
    return None


def find_function_name_by_first_identifier(node, file_content):
    function_name = ""
    for child in traverse_tree(node):
        if child.type == "identifier":
            function_name = get_node_content(child, file_content)
            return function_name
    return None


def find_function_name_outside_definition(node, file_content):
    prev_node = node
    while prev_node.prev_named_sibling:
        prev_node = prev_node.prev_named_sibling
        if prev_node.type == "declaration":
            for sub_node in traverse_tree(prev_node):
                if sub_node.type == "identifier":
                    function_name = get_node_content(sub_node, file_content)
                    return function_name
    return None


def split_function_content(function_content, entity_range, comment_range):
    function_name_by_byte = bytes(function_content, "utf-8")
    function_parts = []
    for index in range(len(entity_range) - 1):
        if [entity_range[index], entity_range[index + 1]] in comment_range:
            continue
        sub_part = str(function_name_by_byte[entity_range[index]:entity_range[index + 1]], "utf-8").strip()
        if sub_part:
            function_parts.append(sub_part)
    function_body = " ".join(function_parts)
    return function_body


def get_node_max_depth(node):
    max_depth = 0
    for sub_node, depth in traverse_tree_with_depth(node):
        if depth > max_depth:
            max_depth = depth
    return max_depth


def get_split_function_content(node, file_content):
    entity_range = []
    comment_range = []
    node_start_line = node.start_byte
    function_content = get_node_content(node, file_content)
    function_lines = len(function_content.split("\n"))
    function_max_depth = get_node_max_depth(node)
    for flag, leaf_node in traverse_tree_to_leaf(node):
        start_byte = leaf_node.start_byte - node_start_line
        end_byte = leaf_node.end_byte - node_start_line
        if flag is False:
            comment_range.append([start_byte, end_byte])
        if start_byte not in entity_range:
            entity_range.append(start_byte)
        if end_byte not in entity_range:
            entity_range.append(end_byte)
    # function_body = split_function_content(function_content, entity_range, comment_range)
    function_body = function_content
    return function_body, function_lines, function_max_depth


def get_function_strings(node, file_content):
    function_strings = []
    for child_node in traverse_tree(node):
        if child_node.type == "string_literal":
            leaf_content = get_node_content(child_node, file_content)
            function_strings.append(leaf_content)
    return function_strings


def parse_file(file_content, c_file_path, error_function, tree_sitter_lib_path):
    C_language = Language(tree_sitter_lib_path, "c")
    parser = Parser()
    parser.set_language(C_language)
    tree = parser.parse(bytes(file_content, "utf8"))
    # cursor = tree.walk()
    # if c_file_path == "D:\\GitHub\\coreutils_8.29\\source\\coreutils\\src\\base64.c":
    #     print("debug")
    function_range_and_content = {}
    function_strings_dict = {}
    for node in traverse_tree(tree):
        # print(node)
        if node.type == "function_definition":
            function_name = find_function_name_normal(node, file_content)
            if not function_name:
                start_point = node.start_point
                end_point = node.end_point
                function_name = find_function_name_outside_definition(node, file_content)
                if not function_name:
                    function_name = find_function_name_by_first_identifier(node, file_content)
                    if not function_name:
                        # raise Exception("cannot find the function name!")
                        error_function.append([c_file_path, start_point, end_point, "unresolved"])
                    else:
                        error_function.append([c_file_path, start_point, end_point, "resolved"])
            # if function_name == "usage":
            #     print("debug")
            start_point = node.start_point
            end_point = node.end_point
            # start_byte = node.start_byte
            # end_byte = node.end_byte
            function_body, function_lines, function_max_depth = get_split_function_content(node, file_content)
            # function_body = get_node_content(node, file_content)
            # if "\"" in function_body:
            #     print("debug")
            function_strings = get_function_strings(node, file_content)
            if function_name in ["if", "switch", "for", "while", "else", "case", "do"]:
                continue
            if function_name not in function_strings_dict:
                function_strings_dict[function_name] = {"start_point": start_point, "end_point": end_point,
                                                        "strings": function_strings}
            else:
                if type(function_strings_dict[function_name]) is dict:
                    function_strings_dict[function_name] = [function_strings_dict[function_name]]
                function_strings_dict[function_name].append(
                    {"start_point": start_point, "end_point": end_point, "strings": function_strings})

            if function_name not in function_range_and_content:
                function_range_and_content[function_name] = {"start_point": start_point, "end_point": end_point,
                                                             "content": function_body, "lines": function_lines,
                                                             "depth": function_max_depth}
            else:
                if type(function_range_and_content[function_name]) is dict:
                    function_range_and_content[function_name] = [function_range_and_content[function_name]]
                function_range_and_content[function_name].append(
                    {"start_point": start_point, "end_point": end_point, "content": function_body,
                     "lines": function_lines, "depth": function_max_depth})
    return function_range_and_content, function_strings_dict, error_function


def write_json(file_name, content):
    with open(file_name, "w") as f:
        json_str = json.dumps(content, indent=2)
        f.write(json_str)


def get_functions_ranges(source_project, source_entities_result_dir, tree_sitter_lib_path):
    C_files_list = (".h", ".c", ".y", ".l")
    c_file_path_list = read_c_files(source_project, C_files_list)
    source_project_name = os.path.basename(source_project)
    function_range_file = os.path.join(source_entities_result_dir, source_project_name + "_function_range_content.json")
    if os.path.exists(function_range_file):
        return c_file_path_list
    file_function_range_content_dict = {}
    function_strings_all = {}
    error_function = []
    for c_file_path in c_file_path_list:
        # print(c_file_path)
        file_content = read_file(c_file_path)
        function_range_and_content, function_strings_dict, error_function = parse_file(file_content, c_file_path, error_function, tree_sitter_lib_path)
        # c_file_relative_path = c_file_path.replace(source_project, "")
        c_file_relative_path = c_file_path
        if c_file_relative_path not in file_function_range_content_dict:
            file_function_range_content_dict[c_file_relative_path] = function_range_and_content
        if c_file_relative_path not in function_strings_all:
            function_strings_all[c_file_relative_path] = function_strings_dict
    write_json(function_range_file, file_function_range_content_dict)
    error_record_file = os.path.join(source_entities_result_dir, source_project_name + "_error.json")
    write_json(error_record_file, error_function)
    function_strings_file = os.path.join(source_entities_result_dir, source_project_name + "_strings.json")
    write_json(function_strings_file, function_strings_all)
    return c_file_path_list