import csv
import json
import os

from tqdm import tqdm


def write_json(file_path, obj):
    with open(file_path, "w") as f:
        json_str = json.dumps(obj)
        f.write(json_str)


def generate_selected_dataset():
    selected_dataset = {}
    flowchart_folder = "/data2/jiaang/binary2binary/IDA_scripts/IDA_flowchart/flowchart_csv_dataset_I"
    with tqdm(total=len(os.listdir(flowchart_folder))) as pbar:
        for csv_file_name in os.listdir(flowchart_folder):
            project_name = csv_file_name.split("-")[0]
            if project_name == "gnu":
                project_name = "gnu-pw-mgr"
            i64_file_path = "IDBs/Dataset-1/" + project_name + "/" + csv_file_name.replace(".csv", "")
            # print(i64_file_path)
            if "_mips_" in csv_file_name:
                continue
            selected_dataset[i64_file_path] = []
            csv_file_path = os.path.join(flowchart_folder, csv_file_name)
            csv_reader = csv.reader(open(csv_file_path, "r"))
            rows = [row for row in csv_reader]
            for line in rows[1:]:
                binary_name, function_address, bb_num = line[0], line[1], line[5]
                function_address = int(function_address, 16)
                selected_dataset[i64_file_path].append(function_address)
            pbar.update()
        pbar.close()
    selected_dataset_file = "selected_dataset_I.json"
    write_json(selected_dataset_file, selected_dataset)


if __name__ == '__main__':
    generate_selected_dataset()