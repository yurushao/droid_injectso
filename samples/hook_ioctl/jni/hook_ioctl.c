#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>

#include "../../../libhook/hook.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "inject-test", __VA_ARGS__))

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
    pid_t pid = getpid();
    LOGI("pid: %d", pid);

    orig_ioctl = do_hook("/system/lib/libbinder.so", hooked_ioctl, "ioctl");
    LOGI("orignal ioctl: %x", orig_ioctl);
}
