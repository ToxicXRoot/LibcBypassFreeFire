#include "hooklibc.h"

int main()

{
  KittyMemory::ProcMap ggp;
  do {
    anogs = KittyMemory::getLibraryMap("libanogs.so");
    sleep(1);
  } while (!anogs.isValid());
  {

    // call the hook libc on when libanogs is loaded  after 5 seconds sleep()
    sleep(5);
    hookFunctions(); // hook libc function 
  }

  return 0;

}
