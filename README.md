# Introduction
flare-dbg is a project meant to aid malware reverse engineers in rapidly developing debugger scripts.

#Installation/setup
1. Install the ```pykd``` windbg extension from: https://pykd.codeplex.com/releases
  1. Download the Bootstrapper dll.
  2. Add the Bootstrapper pykd.dll file into your winext directory. Something like ```%ProgramFiles%\Debugging Tools for Windows\winext```.
  3. Install the latest 0.3.x version of pykd using ```pip install pykd```. 
  4. Ensure you can import ```pykd``` from within windbg: ```.load pykd```.
2. Install ```winappdbg```
  1. ```pip install winappdbg```
3. Setup ```vivisect```
  1. Install vivisect using one of the following options:
    1. Install using setup.py from: https://github.com/williballenthin/vivisect
    2. Download and extract ```vivisect``` and set ```PYTHONPATH``` to the extracted directory.
  2. Ensure you can import vivisect from a python shell: ```import vivisect```.
4. Setup ```flaredbg```
  1. Install flaredbg using ```setup.py```

# Running scripts
There are two options for running scripts:
  1. Create a script directory and set ```PYTHONPATH``` to the newly created script directory and add your scripts here.
  2. Copy scripts to the root of your windbg directory. Something like: ```%ProgramFiles%\Debugging Tools for Windows\```.
Once your script path is setup, scripts are run from the windbg console as follows:
```
> .load pykd
> !py <script_name>
```




