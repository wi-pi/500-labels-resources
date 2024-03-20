# A Picture is Worth 500 Labels: A Case Study of Demographic Disparities in Local Machine Learning Models for Instagram and TikTok Source Code

This repo contains all resources for the paper, "A Picture is Worth 500 Labels: A Case Study of Demographic Disparities in Local Machine Learning Models for Instagram and TikTok" published at Oakland 2024.

We break up the resources into three categories:
1. Dynamic Analysis Code
2. Static Analysis Resources
3. Datasets


## Dynamic Analysis Code

We provide all code written that performs our static analysis.
All resources are under the `Dynamic_Analysis_Code` folder.
Within this folder there are three sub-folders: `OS_Code`, `python_scripts`, and `frida_scripts`.
Each folder will have a README file explaining their respective contents.
The `OS-Code` folder provides all of the source code changes we made to the operating system as raw C++ files.
We wlll also provide our custom ROM within that folder as well.
We are currently working on a custom patching script to deploy those changes, however, we will provide a written tutorial to install the patch yourself for the time being.
The `python_scripts` folder will contain all python related code.
This includes the OS logcat parser and the TikTok experiment script.
Finally, the `frida_scripts` folder contains all Frida scripts used.
There are three main scripts we provide: our native hooking script, our Instagram experiment script, and any other custom scripts we wrote during our research.

## Static Analysis Code

This folder will contain all Apks and native libraries we examined.
We will include a tutorial discussing how we decompiled each component.

## Datasets

This folder will provide the list of datasets with their links.
It will also provide the experimental data we gathered for the experiments.
We will also provide all data used that is not public, meaning all sythetic data used.



