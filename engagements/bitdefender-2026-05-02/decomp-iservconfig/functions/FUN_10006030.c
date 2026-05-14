int FUN_10006030(void)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  FARPROC pFVar4;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dde0;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
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
  puVar1 = DAT_1006b610;
  DAT_1006b6ac = 1;
  if (DAT_1006b614 < 1) {
    if (0 < DAT_1006b618) {
      DAT_1006b618 = 0;
    }
  }
  else {
    DAT_1006b614 = DAT_1006b614 + -1;
  }
  if (((DAT_1006b610 != (undefined4 *)0x0) && (DAT_1006b618 == 0)) && (DAT_1006b614 == 0)) {
    if (DAT_1006b610 != (undefined4 *)0x0) {
      local_8 = 0;
      if ((HMODULE)*DAT_1006b610 != (HMODULE)0x0) {
        pFVar4 = GetProcAddress((HMODULE)*DAT_1006b610,"LogDeinit");
        if (pFVar4 != (FARPROC)0x0) {
          (*pFVar4)(uVar3);
        }
        if ((code *)puVar1[0xd] != (code *)0x0) {
          (*(code *)puVar1[0xd])();
        }
        if ((code *)puVar1[0x10] != (code *)0x0) {
          (*(code *)puVar1[0x10])("logging::CLogDLL::~CLogDLL");
        }
        FreeLibrary((HMODULE)*puVar1);
      }
      FUN_1002e346(puVar1);
    }
    DAT_1006b610 = (undefined4 *)0x0;
  }
  iVar2 = DAT_1006b6ac;
  LOCK();
  DAT_1006b6ac = 0;
  UNLOCK();
  ExceptionList = local_10;
  return iVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_10006150 @ 10006150