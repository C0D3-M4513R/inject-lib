#include <stdio.h>
#include "my_header.h"//Get this header from the build artifacts

int main(){
    char vulkan[16]="rust-vulkan.exe\0";
    FindPid r=find_pid(vulkan);
    printf("Exitcode of findpid=%i\n",r.exitcode);
    if (r.len >=0 && r.exitcode==0) {
        uint32_t pid=r.arr[0];
        int16_t i = inject(pid,"rust_dll.dll");
        printf("Exitcode of inject=%i\n",i);
    }

}
