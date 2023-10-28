This is a quick-and-dirty program that I made so I can see what a set of Action Replay codes actually *does* in a technological sense.

Special thanks to:

* [Wunkolo](https://wunkolo.tumblr.com/post/144418662792), for encrypt/decrypt code for AR v3/v4
* mGBA and their source code, which is effectively the most complete documentation of the Action Replay v3/v4 format I could find on the web. I didn't copy any code, but did learn the format from how they were handling it (while taking my own approach to things like bitpacked enums).
* [EnHacklopedia](https://doc.kodewerx.org/hacking_gba.html#ardescribe), for covering the cases mGBA doesn't and for listing all possible permutations of AR codes (mGBA source code decomposes codes into their component parts; EnHacklopedia does not; this is useful for comparisons).

## Build environment

This program was built using Microsoft Visual Studio Community 2022 with the [Qt Visual Studio Tools](https://marketplace.visualstudio.com/items?itemName=TheQtCompany.QtVisualStudioTools2022) plug-in and Qt Designer. The [version of Qt used](https://doc.qt.io/qtvstools/qtvstools-managing-projects.html#managing-qt-versions) was 5.15.2, 64-bit, for MSVC 2019 x64.

## License

This was a quick-and-dirty two-hour project, so I haven't bothered to even pick a license. I can't imagine anyone'll actually want anything in here; it's all very "get the job done" and not so much "simple and clean."

Qt and its components are licensed under LGPL v3. Per the terms of LGPL, I am required to make [the source code for Qt 5.15.2](https://download.qt.io/archive/qt/5.15/5.15.2/single/) available to you in case you're unable to acquire it on your own. Presently I have a copy saved to my machine.

The Qt Visual Studio Tools plug-in is [GPL-licensed with a special exemption](https://marketplace.visualstudio.com/items/TheQtCompany.QtVisualStudioTools2019/license) which allows its use in developing non-GPL software. Qt Designer has [a similar exception](https://opensource.stackexchange.com/questions/7709/using-qt-designer-to-create-ui-design-for-closed-source-application).