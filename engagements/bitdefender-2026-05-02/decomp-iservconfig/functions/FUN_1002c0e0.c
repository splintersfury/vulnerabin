void __thiscall FUN_1002c0e0(void *this,undefined4 param_1,undefined4 param_2,int *param_3)

{
  int *piVar1;
  code *pcVar2;
  int iVar3;
  undefined1 local_28 [16];
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_10050d20;
  local_10 = ExceptionList;
  local_18 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  Ordinal_8(local_28,local_18);
                    /* WARNING: Load size is inaccurate */
  piVar1 = *this;
  if (piVar1 == (int *)0x0) {
    iVar3 = FUN_1002f620(0x80004003);
LAB_1002c1a6:
    FUN_1002f620(iVar3);
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  iVar3 = (**(code **)(*piVar1 + 0x10))(piVar1,param_2,0,local_28,0,0);
  if (iVar3 == 0) {
    *param_3 = 0;
    param_3[1] = (int)&PTR_vftable_10069aa8;
    Ordinal_8(param_1);
    iVar3 = Ordinal_10(param_1,local_28);
    if (iVar3 < 0) goto LAB_1002c1a6;
  }
  else {
    *param_3 = iVar3;
    param_3[1] = (int)&PTR_vftable_10069ab8;
    Ordinal_8(param_1);
  }
  Ordinal_9(local_28);
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c1c0 @ 1002c1c0