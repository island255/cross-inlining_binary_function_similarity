# Scripts to train the cross-inlining model

Given the raw binaries compiled by different architectures, compiler and optimizations, here are the scripts to generate the datasets for cross-inlining. 

## Dataset

The dataset can download from https://drive.google.com/file/d/1K9ef-OoRBr0X5u8g2mlnYqh9o1i6zFij/view and https://drive.google.com/file/d/1wt7GY-DDp8J_2zeBBVUrcfWIyerg_xLO/view. It is contructed using Binkit (https://github.com/SoftSec-KAIST/BinKit).

## workflow

This repository use the code from repository https://github.com/Cisco-Talos/binary_function_similarity. Please aslo refer it for the details.

1. use IDA_scripts/IDA_flowchart to get all the functions information in the inline binaries and noinline binaries

2. use preprocessing_for_cross_inlining/generate_selected_dataset.py to generate the selected_dataset.json

3. use IDA_scripts/IDA_acfg_disasm to disassemble the binaries and functions

4. use the preprocessing_for_cross_inlining/construct_ground_truth.py to get cross-inlining dataset

5. use the training_for_cross_inlining/Model/Preprocessing to process the dataset inline and dataset noinline

    5.1 processing for dataset noinline (use the processed results in noinline)  -- dataset-2

   ```bash
    docker run --rm \
        -v $(pwd)/../../DBs/Dataset-2/features/training/acfg_disasm_Dataset-2_training:/input \
        -v $(pwd)/Preprocessing/Dataset-2_training:/output \
        -it gnn-preprocessing /code/gnn_preprocessing.py -i /input --training -o /output
    ```
    
    ```bash
    docker run --rm \
        -v $(pwd)/../../DBs/Dataset-2/features/validation/acfg_disasm_Dataset-2_validation:/input \
        -v $(pwd)/Preprocessing/Dataset-2_training:/training_data \
        -v $(pwd)/Preprocessing/Dataset-2_validation:/output \
        -it gnn-preprocessing /code/gnn_preprocessing.py -i /input -d /training_data/opcodes_dict.json -o /output
    ```
    
    ```bash
    docker run --rm \
        -v $(pwd)/../../DBs/Dataset-2/features/testing/acfg_disasm_Dataset-2_testing:/input \
        -v $(pwd)/Preprocessing/Dataset-2_training:/training_data \
        -v $(pwd)/Preprocessing/Dataset-2_testing:/output \
        -it gnn-preprocessing /code/gnn_preprocessing.py -i /input -d /training_data/opcodes_dict.json -o /output
   ```

    5.2 processing for dataset inline (use the opcode dict obtained in noinline) -- dataset-1
    
    ```bash
   docker run --rm     \
       -v $(pwd)/../../DBs/Dataset-1/features/training/acfg_disasm_Dataset-1_training:/input  \
       -v $(pwd)/Preprocessing/Dataset-2_training:/training_data    \
       -v $(pwd)/Preprocessing/Dataset-1_training:/output     \
       -it gnn-preprocessing /code/gnn_preprocessing.py \
       -i /input -d /training_data/opcodes_dict.json -o /output
      ```
   ```bash
   docker run --rm     \
       -v $(pwd)/../../DBs/Dataset-1/features/validation/acfg_disasm_Dataset-1_validation:/input  \
       -v $(pwd)/Preprocessing/Dataset-2_training:/training_data    \
       -v $(pwd)/Preprocessing/Dataset-1_validation:/output    \
       -it gnn-preprocessing /code/gnn_preprocessing.py \
       -i /input -d /training_data/opcodes_dict.json -o /output
   ```
   ```bash
   docker run --rm     \
       -v $(pwd)/../../DBs/Dataset-1/features/testing/acfg_disasm_Dataset-1_testing:/input  \
       -v $(pwd)/Preprocessing/Dataset-2_training:/training_data    \
       -v $(pwd)/Preprocessing/Dataset-1_testing:/output     \
       -it gnn-preprocessing /code/gnn_preprocessing.py \
       -i /input -d /training_data/opcodes_dict.json -o /output
   ```

6. use training_for_cross_inlining/concentrate_dataset_1_and_2.py to combine two dataset


     

7. build_docker

```bash
nvidia-docker run \
    -v $(pwd)/../../DBs:/input \
    -v $(pwd)/Preprocessing:/preprocessing \
    -v $(pwd)/NeuralNetwork_cross_inlining/:/output \
    -v $(pwd)/NeuralNetwork_cross_inlining/code:/code \
    --name gnn-neuralnetwork_cross_inlining \
    -it gnn-neuralnetwork_base 
```

change  line 77 in training_for_cross_inlining\Model\code\core\config.py to respectively train model for pattern1 pattern2 pattern3


```bash
python3 /code/gnn.py --train --num_epochs 128 \
    --model_type embedding --training_mode pair \
    --features_type opc --dataset one \
    -c /output/model_checkpoint_pattern1_epoch_128 \
    -o /output/Dataset_cross_inlining_training_GSSN_opc_pair_pattern1_epoch_128
```


## note

Note that binaries compiled in architecture **mips-32 mips-64** cannot be processed by the capstone, thus must be excluded in the subsequent process.