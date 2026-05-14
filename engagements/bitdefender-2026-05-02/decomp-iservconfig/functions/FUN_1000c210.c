DWORD * __thiscall FUN_1000c210(void *this,wchar_t *param_1)

{
  wchar_t *pwVar1;
  DWORD DVar2;
  HMODULE *local_1c;
  int local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e59d;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  DVar2 = timeGetTime();
  pwVar1 = param_1;
  *(DWORD *)this = DVar2;
  FUN_10034931((wchar_t *)((int)this + 4),0x102,param_1,0xffffffff);
  _wcscat_s((wchar_t *)((int)this + 4),0x104,L"()");
  FUN_10034931((wchar_t *)((int)this + 0x20c),0x104,pwVar1,0xffffffff);
  if (DAT_1006b614 + DAT_1006b618 != 0) {
    local_1c = FUN_10005210();
    LOCK();
    local_18 = 1;
    UNLOCK();
    local_8 = 0;
    if (local_1c == (HMODULE *)0x0) {
      local_1c = FUN_10005210();
      LOCK();
      local_18 = 2;
      UNLOCK();
    }
    param_1 = (wchar_t *)0x20;
    FUN_10003200((int)local_1c,1,&param_1,0x10000000,(int)this + 0x20c,L"-> %s");
    LOCK();
    UNLOCK();
    while (local_18 = local_18 + -1, -1 < local_18) {
      FUN_10006030();
      LOCK();
      UNLOCK();
    }
    LOCK();
    UNLOCK();
  }
  ExceptionList = local_10;
  return (DWORD *)this;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000c320 @ 1000c320