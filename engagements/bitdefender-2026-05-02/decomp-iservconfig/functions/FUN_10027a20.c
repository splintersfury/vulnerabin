void __thiscall FUN_10027a20(void *this,short *param_1)

{
  code *pcVar1;
  int iVar2;
  short local_28 [4];
  int local_20;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1005043d;
  local_10 = ExceptionList;
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  *(undefined4 *)this = 0;
  if (*param_1 == 8) {
    FUN_10027900(this,*(int *)(param_1 + 4));
  }
  else {
    Ordinal_8(local_28,local_18);
    local_8 = 0;
    if ((local_28 != param_1) || (local_28[0] != 8)) {
      iVar2 = Ordinal_12(local_28,param_1,0,8);
      if (iVar2 < 0) {
        FUN_1002f620(iVar2);
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
    FUN_10027900(this,local_20);
    Ordinal_9(local_28);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027ae0 @ 10027ae0