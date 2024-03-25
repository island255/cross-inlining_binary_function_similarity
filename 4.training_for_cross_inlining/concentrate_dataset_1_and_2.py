import json
import os
import shutil


def read_json(file_path):
    with open(file_path, "r") as f:
        file_content = json.load(f)
        return file_content


def write_json(file_path, obj):
    dir_folder = os.path.dirname(file_path)
    if os.path.exists(dir_folder) is False:
        os.makedirs(dir_folder)
    with open(file_path, "w") as f:
        json_str = json.dumps(obj)
        f.write(json_str)


def concentrate_two_dataset(preprocessing_folder, dataset_1_training, dataset_2_training, dest_dataset_training,
                            graph_dict_file):
    dataset_1_training_content = read_json(os.path.join(preprocessing_folder, dataset_1_training, graph_dict_file))
    dataset_2_training_content = read_json(os.path.join(preprocessing_folder, dataset_2_training, graph_dict_file))
    concentrated_dict = {**dataset_1_training_content, **dataset_2_training_content}
    dest_file_path = os.path.join(preprocessing_folder, dest_dataset_training, graph_dict_file)
    write_json(dest_file_path, concentrated_dict)


def main():
    preprocessing_folder = "/path/to/Models/GGSNN-GMN/Preprocessing/"
    dataset_1_training = "Dataset-1_training"
    dataset_1_validation = "Dataset-1_validation"
    dataset_1_testing = "Dataset-1_testing"
    dataset_2_training = "Dataset-2_training"
    dataset_2_validation = "Dataset-2_validation"
    dataset_2_testing = "Dataset-2_testing"
    graph_dict_file = "graph_func_dict_opc_200.json"
    dest_dataset_training = "Dataset-1+2_training"
    dest_dataset_validation = "Dataset-1+2_validation"
    dest_dataset_testing = "Dataset-1+2_testing"
    print("concentrating two dataset: training")
    concentrate_two_dataset(preprocessing_folder, dataset_1_training, dataset_2_training,
                            dest_dataset_training, graph_dict_file)
    print("concentrating two dataset: validation")
    concentrate_two_dataset(preprocessing_folder, dataset_1_validation, dataset_2_validation,
                            dest_dataset_validation, graph_dict_file)
    print("concentrating two dataset: testing")
    concentrate_two_dataset(preprocessing_folder, dataset_1_testing, dataset_2_testing,
                            dest_dataset_testing, graph_dict_file)
    print("copying opcodes dict")
    opcode_dict_file = "opcodes_dict.json"
    shutil.copyfile(os.path.join(preprocessing_folder, dataset_2_training, opcode_dict_file),
                    os.path.join(preprocessing_folder, dest_dataset_training, opcode_dict_file))


if __name__ == '__main__':
    main()