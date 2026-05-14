undefined4 __fastcall FUN_100131f0(undefined4 *param_1)

{
  undefined4 *this;
  uint *puVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined1 local_15 [5];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004edb0;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_8 = 0;
  puVar4 = param_1 + 10;
  if (0xf < (uint)param_1[0xf]) {
    puVar4 = (undefined4 *)param_1[10];
  }
  param_1[0xe] = 0;
  this = param_1 + 7;
  *(undefined1 *)puVar4 = 0;
  puVar1 = (uint *)*this;
  param_1[8] = puVar1;
  local_15[0] = *(undefined1 *)(param_1 + 2);
  if (puVar1 == (uint *)param_1[9]) {
    FUN_100174f0(this,puVar1,local_15);
  }
  else {
    *(undefined1 *)puVar1 = local_15[0];
    param_1[8] = param_1[8] + 1;
  }
  local_8 = 0xffffffff;
  param_1[4] = param_1[4] + 1;
  param_1[5] = param_1[5] + 1;
  if (*(char *)(param_1 + 3) == '\0') {
    uVar5 = (*(code *)**(undefined4 **)*param_1)(uVar3);
    param_1[2] = uVar5;
  }
  else {
    *(undefined1 *)(param_1 + 3) = 0;
  }
  if (param_1[2] != -1) {
    puVar1 = (uint *)param_1[8];
    local_15[0] = (undefined1)param_1[2];
    if (puVar1 == (uint *)param_1[9]) {
      FUN_100174f0(this,puVar1,local_15);
    }
    else {
      *(undefined1 *)puVar1 = local_15[0];
      param_1[8] = param_1[8] + 1;
    }
  }
  iVar2 = param_1[2];
  if (iVar2 == 10) {
    param_1[6] = param_1[6] + 1;
    param_1[5] = 0;
  }
  else if (0xf5 < iVar2 + 1U) {
    param_1[0x10] = "invalid string: ill-formed UTF-8 byte";
    ExceptionList = local_10;
    return 0xe;
  }
                    /* WARNING: Could not recover jumptable at 0x100132ce. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  uVar5 = (*(code *)(&PTR_LAB_10013914)[(byte)(&DAT_100139c5)[iVar2]])();
  return uVar5;
}


// FUNCTION_END

// FUNCTION_START: FUN_10013b40 @ 10013b40