HMODULE * FUN_10005210(void)

{
  uint uVar1;
  FARPROC pFVar2;
  HMODULE *ppHVar3;
  int iVar4;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dd44;
  local_10 = ExceptionList;
  uVar1 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  LOCK();
  UNLOCK();
  if (DAT_1006b6ac != 0) {
    do {
      DAT_1006b6ac = 1;
      Sleep(1);
      LOCK();
      UNLOCK();
    } while (DAT_1006b6ac != 0);
  }
  ppHVar3 = DAT_1006b610;
  DAT_1006b6ac = 1;
  if ((DAT_1006b618 == 0) && (DAT_1006b614 == 0)) {
    if ((DAT_1006b610 != (HMODULE *)0x0) && (DAT_1006b610 != (HMODULE *)0x0)) {
      local_8 = 0;
      if (*DAT_1006b610 != (HMODULE)0x0) {
        pFVar2 = GetProcAddress(*DAT_1006b610,"LogDeinit");
        if (pFVar2 != (FARPROC)0x0) {
          (*pFVar2)(uVar1);
        }
        if (ppHVar3[0xd] != (HMODULE)0x0) {
          (*(code *)ppHVar3[0xd])();
        }
        if (ppHVar3[0x10] != (HMODULE)0x0) {
          (*(code *)ppHVar3[0x10])("logging::CLogDLL::~CLogDLL");
        }
        FreeLibrary(*ppHVar3);
      }
      local_8 = 0xffffffff;
      FUN_1002e346(ppHVar3);
    }
    ppHVar3 = (HMODULE *)operator_new(0x48);
    local_8 = 1;
    _memset(ppHVar3,0,0x48);
    DAT_1006b610 = FUN_10002ff0(ppHVar3);
    if (DAT_1006b60c == '\0') {
      iVar4 = _atexit(guard_check_icall);
      DAT_1006b60c = iVar4 == 0;
    }
  }
  DAT_1006b614 = DAT_1006b614 + 1;
  LOCK();
  DAT_1006b6ac = 0;
  UNLOCK();
  ExceptionList = local_10;
  return DAT_1006b610;
}


// FUNCTION_END

// FUNCTION_START: FUN_10005360 @ 10005360