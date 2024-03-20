# Dynamic Analysis

This folder contains the most information.
There are three main folders: frida_scripts, OS_Code, and python_scripts.
Each folder contains unique components of our methodology.

## Frida Scripts

There are two main components in this folder: Instagram's experiment and our native hooks script.
The Instagram experiment has two scripts, one for each APK.
During our study Instagram had an update on one of the devices. 
We Decided to remake the script to fit the newer update and update all phones to the newest version.
You can see how much of the first script changed from just a single update.
Entire objects within the pipeline were no longer created or utilized.
This example is interesting because, in my opinion, it highlights one of the major difficulties with designing a scalable system around obfuscated Android code.
We include both scripts here for two reasons: transparency and for others to test both versions of the app.

Our final script we include here is the native script.
This is code we used to trace data within the native libraries.
As you will see, the code is messy and comment heavy.
We decided to leave the code in its current state to emphasize the manual component of our work.
When comparing the Instagram and native scripts you will notice that the Instagram script is very concise in comparison.
This juxtaposition is purposeful as we want to show how much manual effort had to be applied to the native libraries.
To analyze native execution chains a user **must** perform dynamic analysis even with the most cutting edge tools.
TikTok and Instagram both heavily utilize runtime addressing, meaning that they jump to addresses that are determined at runtime.
Our code shows that not only are these addresses never in the same register, they can happen in any function.
You almost must note addresses when logging the contents of the register to properly rebuild the native pipelines.


## OS Code

This folder is the most complicated folder and will require several updates past the first few to fully complete.
For the sake of transparency and to allow knowledgeable users to be able to build our OS instrumentation we provide all code we used.
In future updates, we will provide a patching script that will run and patch our changes on a freshly pulled version of Lineage.
Our operating system was vital when performing our initial analysis of the APKs.
It showed us where to start looking when analyzing the codebase.
As any security researcher knows who has analyzed obfuscated code will tell you, finding where to start is extremely challenging.
Our operating system helped with that as we are able to pin point where ML is likely happening.
