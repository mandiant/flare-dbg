# Windbg decoder scripts
The general idea behind the ```flaredbg.py``` is to create a collection of convenience functions to quickly decode obfuscated strings and automate other debugger tasks.

## Finding arguments
The ```get_call_list``` function will look for the number of push arguments and the specific registers you ask for. Each register argument is its own dictionary, i.e. ```{'eax':5}```. Each push argument is simply append to the end of the list.

```get_call_list``` returns the calling virtual address and the arguments. 

## Allocating memory
The ```flaredbg.py``` script contains several wrapper functions to read/write/malloc/free memory.

## Running the function
Usually you will just call the ```flaredbg.DebugUtils.call``` function, passing the function address, the argument list, and the from virtual address. Other convenience functions exist including ```run_to_return``` to only run to a specific virtual address.

# Examples
An example script named ```example.py``` can be used as a basic template for new decoder scripts.
An example script named ```example2.py``` is slightly more complicated.
