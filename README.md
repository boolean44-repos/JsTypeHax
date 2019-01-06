# JsTypeHax

Wii U browser exploit for system version 5.5.2 and 5.5.3.  
Requires a valid payload ("code550.bin") in the root dir and the release files from the [wiiuhaxx_common repo](https://github.com/wiiu-env/wiiuhaxx_common/releases) inside a subfolder "wiiuhaxx_common".

Tested with the [homebrew launcher 1.4 payload](https://github.com/dimok789/homebrew_launcher/releases/download/1.4/codebin.zip)

# Requirements
A webserver with php support.

# The bug

`CVE-2013-2857`, Use after free https://bugs.chromium.org/p/chromium/issues/detail?id=240124 .