#include "syscalls.h"


BOOL InitializeSyscalls() {
#if defined(HW_SYSCALLS)
   if(!InitHWSyscalls()){
      DebugPrint("[i] Successfully initiadted HWSyscalls...\n");
      return FALSE;
   }
#endif
   return TRUE;
}
