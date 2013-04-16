#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "inject-test", __VA_ARGS__))

void _init(char *args)
{
    LOGI("lib loaded ...");
}

void so_entry(char *p)
{
    pid_t pid = getpid();
    LOGI("pid: %d", pid);
}
