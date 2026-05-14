undefined4 * __thiscall FUN_100277f0(void *this,int param_1)

{
  code *pcVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  undefined4 *puVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100503c4;
  local_10 = ExceptionList;
  uVar2 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  piVar3 = (int *)operator_new(0xc);
  local_8 = 0;
  if (piVar3 == (int *)0x0) {
    piVar3 = (int *)0x0;
  }
  else {
    piVar3[0] = 0;
    piVar3[1] = 0;
    piVar3[2] = 0;
    piVar3[1] = 0;
    piVar3[2] = 1;
    iVar4 = Ordinal_2(param_1,uVar2);
    *piVar3 = iVar4;
    if ((iVar4 == 0) && (param_1 != 0)) {
      FUN_1002f620(0x8007000e);
      goto LAB_10027891;
    }
  }
  local_8 = 0xffffffff;
  *(int **)this = piVar3;
  if (piVar3 != (int *)0x0) {
    ExceptionList = local_10;
    return (undefined4 *)this;
  }
LAB_10027891:
  FUN_1002f620(0x8007000e);
  pcVar1 = (code *)swi(3);
  puVar5 = (undefined4 *)(*pcVar1)();
  return puVar5;
}


// FUNCTION_END

// FUNCTION_START: FUN_100278a0 @ 100278a0