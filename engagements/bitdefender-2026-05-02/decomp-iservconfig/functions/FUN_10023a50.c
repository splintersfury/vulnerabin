int * __thiscall FUN_10023a50(void *this,int *param_1,byte *param_2,undefined1 *param_3)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  byte *pbVar7;
  uint uVar8;
  undefined1 uVar9;
  byte *pbVar10;
  int local_4c [3];
  undefined8 local_40;
  int *local_34;
  undefined1 *local_30;
  int *local_2c;
  int *local_28;
  int *local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_100500bd;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  local_30 = param_3;
  local_34 = param_1;
  local_24 = (int *)this;
  piVar6 = FUN_10014a40(this,local_4c,param_2);
  local_40 = *(undefined8 *)piVar6;
  local_28 = (int *)piVar6[2];
  if (*(char *)((int)local_28 + 0xd) == '\0') {
    pbVar7 = (byte *)(local_28 + 4);
    if (0xf < (uint)local_28[9]) {
      pbVar7 = *(byte **)pbVar7;
    }
    pbVar10 = param_2;
    if (0xf < *(uint *)(param_2 + 0x14)) {
      pbVar10 = *(byte **)param_2;
    }
    uVar8 = FUN_100148a0(pbVar10,*(uint *)(param_2 + 0x10),pbVar7,local_28[8]);
    if (-1 < (int)uVar8) {
      uVar9 = 0;
      goto LAB_10023b9f;
    }
  }
  if (local_24[1] == 0x4924924) {
    FUN_10001840();
    pcVar3 = (code *)swi(3);
    piVar6 = (int *)(*pcVar3)();
    return piVar6;
  }
  iVar1 = *local_24;
  local_2c = local_24;
  local_14 = 0;
  local_28 = (int *)0x0;
  piVar6 = (int *)operator_new(0x38);
  piVar6[4] = 0;
  piVar6[8] = 0;
  piVar6[9] = 0;
  iVar2 = *(int *)(param_2 + 4);
  iVar4 = *(int *)(param_2 + 8);
  iVar5 = *(int *)(param_2 + 0xc);
  piVar6[4] = *(int *)param_2;
  piVar6[5] = iVar2;
  piVar6[6] = iVar4;
  piVar6[7] = iVar5;
  *(undefined8 *)(piVar6 + 8) = *(undefined8 *)(param_2 + 0x10);
  param_2[0x10] = 0;
  param_2[0x11] = 0;
  param_2[0x12] = 0;
  param_2[0x13] = 0;
  param_2[0x14] = 0xf;
  param_2[0x15] = 0;
  param_2[0x16] = 0;
  param_2[0x17] = 0;
  *param_2 = 0;
  *(undefined1 *)(piVar6 + 10) = *local_30;
  iVar2 = *(int *)(local_30 + 8);
  piVar6[0xd] = *(int *)(local_30 + 0xc);
  piVar6[0xc] = iVar2;
  *local_30 = 0;
  *(undefined4 *)(local_30 + 8) = 0;
  *(undefined4 *)(local_30 + 0xc) = 0;
  *piVar6 = iVar1;
  piVar6[1] = iVar1;
  piVar6[2] = iVar1;
  *(undefined2 *)(piVar6 + 3) = 0;
  local_28 = Insert_node(local_24,(int *)local_40,local_40._4_4_,piVar6);
  uVar9 = 1;
  param_1 = local_34;
LAB_10023b9f:
  *param_1 = (int)local_28;
  *(undefined1 *)(param_1 + 1) = uVar9;
  ExceptionList = local_1c;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023bd0 @ 10023bd0