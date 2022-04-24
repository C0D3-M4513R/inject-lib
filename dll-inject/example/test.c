#include <string.h>
#include <stdio.h>
#include "dll-inject.h"//Get this header from the build artifacts

int main(){
    char vulkan[16]=u8"rust-vulkan.exe";
    FindPid r=find_pid(vulkan, strlen(vulkan));
    printf("Exitcode of findpid=%i arr=%p len=%zu\n",r.exitcode,r.arr,r.len);
    if (r.len >=0 && r.exitcode==0) {
        uint32_t pid=r.arr[0];
        char dll[14]=u8"rust_dll.dll";
        int16_t i = inject(pid, dll, strlen(dll));
        printf("Exitcode of inject=%i\n",i);
        free(r.arr);
    }
    return 0;
}
