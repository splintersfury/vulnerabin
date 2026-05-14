int * __thiscall FUN_100183d0(void *this,uint *param_1)

{
  int iVar1;
  code *pcVar2;
  byte *pbVar3;
  uint uVar4;
  int *piVar5;
  uint *puVar6;
  int *local_28;
  int local_24;
  int *local_20;
  void *local_1c;
  int *local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f375;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = this;
  FUN_10014a40(this,(int *)&local_28,(byte *)param_1);
  if (*(char *)((int)local_20 + 0xd) == '\0') {
    pbVar3 = (byte *)(local_20 + 4);
    if (0xf < (uint)local_20[9]) {
      pbVar3 = *(byte **)pbVar3;
    }
    puVar6 = param_1;
    if (0xf < param_1[5]) {
      puVar6 = (uint *)*param_1;
    }
    uVar4 = FUN_100148a0((byte *)puVar6,param_1[4],pbVar3,local_20[8]);
    if (-1 < (int)uVar4) goto LAB_100184ad;
  }
  if (*(int *)((int)this + 4) == 0x4924924) {
    FUN_10001840();
    pcVar2 = (code *)swi(3);
    piVar5 = (int *)(*pcVar2)();
    return piVar5;
  }
                    /* WARNING: Load size is inaccurate */
  iVar1 = *this;
  local_8 = 0;
  local_18 = (int *)0x0;
  local_1c = this;
  piVar5 = (int *)operator_new(0x38);
  local_8 = 1;
  local_18 = piVar5;
  FUN_100056d0(piVar5 + 4,param_1);
  local_8 = CONCAT31(local_8._1_3_,2);
  *(undefined1 *)(piVar5 + 10) = 0;
  FUN_1000f600(piVar5 + 0xc,'\0');
  *piVar5 = iVar1;
  piVar5[1] = iVar1;
  piVar5[2] = iVar1;
  *(undefined2 *)(piVar5 + 3) = 0;
  local_20 = Insert_node(local_14,local_28,local_24,piVar5);
LAB_100184ad:
  ExceptionList = local_10;
  return local_20 + 10;
}


// FUNCTION_END

// FUNCTION_START: FUN_100184d0 @ 100184d0