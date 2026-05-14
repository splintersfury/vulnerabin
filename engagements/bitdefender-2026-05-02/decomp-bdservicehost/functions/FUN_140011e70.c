void FUN_140011e70(void)

{
  undefined8 *puVar1;
  FARPROC pFVar2;
  
  LOCK();
  UNLOCK();
  if (DAT_14007d640 != 0) {
    do {
      DAT_14007d640 = 1;
      Sleep(1);
      LOCK();
      UNLOCK();
    } while (DAT_14007d640 != 0);
  }
  puVar1 = DAT_14007d4f8;
  DAT_14007d640 = 1;
  if (DAT_14007d500 < 1) {
    if (0 < DAT_14007d504) {
      DAT_14007d504 = 0;
    }
  }
  else {
    DAT_14007d500 = DAT_14007d500 + -1;
  }
  if (((DAT_14007d4f8 != (undefined8 *)0x0) && (DAT_14007d504 == 0)) && (DAT_14007d500 == 0)) {
    if (DAT_14007d4f8 != (undefined8 *)0x0) {
      if ((HMODULE)*DAT_14007d4f8 != (HMODULE)0x0) {
        pFVar2 = GetProcAddress((HMODULE)*DAT_14007d4f8,"LogDeinit");
        if (pFVar2 != (FARPROC)0x0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
        if (puVar1[0xd] != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
        if (puVar1[0x10] != 0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)("logging::CLogDLL::~CLogDLL");
        }
        FreeLibrary((HMODULE)*puVar1);
      }
      FUN_14002f180();
    }
    DAT_14007d4f8 = (undefined8 *)0x0;
  }
  LOCK();
  DAT_14007d640 = 0;
  UNLOCK();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140011fa0 @ 140011fa0