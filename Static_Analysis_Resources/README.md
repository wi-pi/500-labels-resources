# Static Analysis Resources

In this folder we provide the static analysis resources we used.
This includes APKs and elf libraries.
We will also include a tutorial for how to extract the interpreted Java code from the APK files.
This folder will contain the least amount of code.
We manually analyzed all Java and ELF files.
For all code samples, refer to the dynamic analysis folder.

## APKs

This folder contains all APKs used for analysis.
We will include split APKs for both devices.
However, directly installing these APKs maybe a challenge.
Analysis was done on both a Pixel 4XL and Pixel 4.
We provide the APKs for the Pixel 4.
The Pixel 4XL APKs were not used for the final Frida scripts.
If you would like the 4XL APKs email me at jwwest@wisc.edu.
If there is enough demand they will be added later.

Instagram and TikTok both have two versions.
The APK discussed in the paper is the version denoted by a 2.
When running the Instagram Frida script please refer to the second APK.
As for TikTok, both versions of the app will work with the Frida script as we hook into the callback wrapper function which is an Android function not TikTok's.

Finally, we also include TikTok's split APKs.
These are not relevant for Instagram as they are just driver specific pieces of code.
However, for TikTok they are very relevant as they create the ML native connection.
This detail is important as it shows how an app can circumvent all ML detection.
The Pitaya split is the one containing the startup code.
However, these splits are for the Pixel 4XL they will not work on the Pixel 4.
If we get enough requests we will add the current splits.
They are a little more complicated to pull than on the rooted operating system.

## Static Libraries

This folder contains all shared libraries used by both apps.
Instagram's shared libraries were not examined for this work as we were able to work with the model at the Java level.
However, TikTok's libraries are very important.
`libbytenn.so` is where the ML happens.
The libraries provided for Instagram are not up to date.
They are included for transparency as, again, we did not explore Instagram's natives to capture our results.
We did, however, read through them to make sure that ML was not happening at the native level.
