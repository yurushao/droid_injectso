#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>

#include "../../../libhook/hook.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "hook-ioctl", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "hook-ioctl", __VA_ARGS__))

void _init(char *args)
{
    LOGI("lib loaded ...");
}

int (*orig_ioctl)(int, int, ...);

int hooked_ioctl(int fd, int cmd, void *data)
{
    LOGI("ioctl is invoked ...");
    // do something here

    return (*orig_ioctl)(fd, cmd, data);
}

void so_entry(char *p)
{
    char *sym = "ioctl";

    // servicemanager does not use /system/lib/libbinder.so
    // therefore, if you want to hook ioctl of servicemanager
    // please change module_path to /system/bin/servicemanager
    char *module_path = "/system/lib/libbinder.so";
    
    orig_ioctl = do_hook(module_path, hooked_ioctl, sym);

    if ( orig_ioctl == 0 )
    {
        LOGE("[+] hook %s failed", sym);
        return ;
    }

    LOGI("orignal ioctl: 0x%x", orig_ioctl);
}
