# JsTypeHax

Wii U browser exploit for system version 5.5.2 and 5.5.3.  
This PoC currently uses the homebrew launcher 1.4 payload, you can find the original file [here](https://github.com/dimok789/homebrew_launcher/releases/download/1.4/codebin.zip) .   
To create a own usable payload, grab any `code550.bin` and `wiiuhaxx_loader.bin` from the [wiiuhaxx_common repo](https://github.com/wiiu-env/wiiuhaxx_common/releases) and place it in root of this repo. 
Afterwards you can convert it to a JS arrays using `codebin2js.py`, replace line 53-56 on the `index.html` with this output.

# Dependencies
Python 3

# The bug

`CVE-2013-2857`, Use after free https://bugs.chromium.org/p/chromium/issues/detail?id=240124 .