import os
import subprocess


def read_binary_list(projectdir):
    """
    get all binary file's path
    """
    binary_paths = []
    for root, dirs, files in os.walk(projectdir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if "." not in file_name:
                binary_paths.append(file_path)
    return binary_paths


def write_file(path, content):
    if os.path.exists(os.path.dirname(path)) is False:
        os.makedirs(os.path.dirname(path))
    log_file = open(path, "w")
    log_file.write(content)
    log_file.close()


def extract_debug_dump_information(readelf_file_path, binary_file_path, result_dir):
    output_dir = result_dir

    command = "{} --debug-dump=decodedline  {}".format(readelf_file_path, binary_file_path)
    ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    if ret.returncode == 0:
        write_file(os.path.join(output_dir, os.path.basename(binary_file_path)), ret.stdout)
    else:
        print(ret.stderr)


