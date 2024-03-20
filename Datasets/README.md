# Datasets

This folder contains all of the data that is not publicly available.
We provide the synthetic dataset and the dataset where we removed the background from the images.
This data was only used when evaluating Instagram.
For TikTok, FairFace was used for the evaluation.

## Results Folder
Within the results folder we provide all raw data points we used for figure generation.
These results are gathered using the Frida scripts within the dynamic analysis folder.
For the Instagram's evaluation we provide three different files.
Each file contains a single dataset that we gave to instagram for each evaluation.

The Facial data file contains all the synthetic and real data points for the facial concept evaluations.
The fairface data file is the results of fairface on the model.
Finally, the imagenet file contains model predictions on our hand selected subset of imagenet data. 