HMODULE * FUN_14000eb20(void)

{
  int iVar1;
  FARPROC pFVar2;
  HMODULE *ppHVar3;
  
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
  ppHVar3 = DAT_14007d4f8;
  DAT_14007d640 = 1;
  if ((DAT_14007d504 == 0) && (DAT_14007d500 == 0)) {
    if ((DAT_14007d4f8 != (HMODULE *)0x0) && (DAT_14007d4f8 != (HMODULE *)0x0)) {
      if (*DAT_14007d4f8 != (HMODULE)0x0) {
        pFVar2 = GetProcAddress(*DAT_14007d4f8,"LogDeinit");
        if (pFVar2 != (FARPROC)0x0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
        if (ppHVar3[0xd] != (HMODULE)0x0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)();
        }
        if (ppHVar3[0x10] != (HMODULE)0x0) {
          (*(code *)PTR__guard_dispatch_icall_14005b538)("logging::CLogDLL::~CLogDLL");
        }
        FreeLibrary(*ppHVar3);
      }
      FUN_14002f180();
    }
    ppHVar3 = (HMODULE *)operator_new(0x90);
    *ppHVar3 = (HMODULE)0x0;
    ppHVar3[1] = (HMODULE)0x0;
    ppHVar3[2] = (HMODULE)0x0;
    ppHVar3[3] = (HMODULE)0x0;
    ppHVar3[4] = (HMODULE)0x0;
    ppHVar3[5] = (HMODULE)0x0;
    ppHVar3[6] = (HMODULE)0x0;
    ppHVar3[7] = (HMODULE)0x0;
    ppHVar3[8] = (HMODULE)0x0;
    ppHVar3[9] = (HMODULE)0x0;
    ppHVar3[10] = (HMODULE)0x0;
    ppHVar3[0xb] = (HMODULE)0x0;
    ppHVar3[0xc] = (HMODULE)0x0;
    ppHVar3[0xd] = (HMODULE)0x0;
    ppHVar3[0xe] = (HMODULE)0x0;
    ppHVar3[0xf] = (HMODULE)0x0;
    ppHVar3[0x10] = (HMODULE)0x0;
    ppHVar3[0x11] = (HMODULE)0x0;
    DAT_14007d4f8 = FUN_140001710(ppHVar3);
    if (DAT_14007d4f0 == '\0') {
      iVar1 = atexit(_guard_check_icall);
      DAT_14007d4f0 = iVar1 == 0;
    }
  }
  DAT_14007d500 = DAT_14007d500 + 1;
  LOCK();
  DAT_14007d640 = 0;
  UNLOCK();
  return DAT_14007d4f8;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000ec80 @ 14000ec80