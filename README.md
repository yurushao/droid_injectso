# droid-injectso


A shared libraries injection tool and ELF hook engine of Android.

Please compile them with <code>android-ndk-r8e</code>, or you may need to rewrite <code>Android.mk</code>.

Has been tested on Android 2.2, 2.3 and 4.1, and *root privilege is REQUIRED.*

Special thanks to the author of <code>libinject</code> http://bbs.pediy.com/showthread.php?t=141355


### Compilation

Enter each source directory and run <code>ndk-build</code> provided by <code>android-ndk-r8e</code>.

	$ cd injector
	$ $NDK/ndk-build
	$ cd ../sample
	$ $NDK/ndk-build
	
<code>$NDK</code> is the root directory of <code>android-ndk-r8e</code>.

Also, you can find pre-compiled binaries in <code>bin</code>.

### Usage

We can use <code>injector</code> to inject a shared library into arbitrary processes. Let's take <code>libtest.so</code> as an example.

First, push both <code>injector</code> and <code>libtest.so</code> into a writeable location (e.g. <code>/data/local/</code>) of your device (or emulator).

	$ adb push injector /data/local/
	$ adb push libtest.so /data/local/
	
Then, set the permission of <code>injector</code> as executable.

	$ adb shell chmod 755 /data/local/injector
	
Next, you can refer to <code>injector</code>'s usage information to inject <code>libtest.so</code> into target processes.

	$ adb shell /data/local/injector -h
	Usage: injector -p pid -l libpath
    -h  --help      Display this usage information.
    -p  --pid       PID of target process.
    -l  --libpath   Absolute path of the shared library that will be injected.
    
What should be noticed is that injection may be failed if you specify a *relative path*  after <code>-l</code> (or <code>--libpath</code>) option.

### Hook engine
Please take a look at the sample project <code>samples/hook_ioctl</code>.

### Reference
1. http://bbs.pediy.com/showthread.php?t=141355
2. http://www.codeproject.com/Articles/70302/Redirecting-functions-in-shared-ELF-libraries
