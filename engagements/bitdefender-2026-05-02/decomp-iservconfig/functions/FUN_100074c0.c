void __cdecl
FUN_100074c0(undefined4 param_1,undefined4 *param_2,undefined4 param_3,int *param_4,int param_5,
            undefined4 param_6,char *param_7,uint param_8)

{
  uint *puVar1;
  char cVar2;
  undefined4 uVar3;
  code *pcVar4;
  undefined4 *puVar5;
  int *piVar6;
  uint uVar7;
  short ****ppppsVar8;
  int iVar9;
  char ****ppppcVar10;
  uint uVar11;
  _Facet_base local_54 [4];
  int *local_50;
  int *local_4c;
  uint local_48;
  char ***local_44 [4];
  undefined4 local_34;
  uint local_30;
  short ***local_2c [4];
  uint local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004df75;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  if ((param_8 == 0) || ((*param_7 != '+' && (*param_7 != '-')))) {
    local_48 = 0;
  }
  else {
    local_48 = 1;
  }
  if (((((*(uint *)(param_5 + 0x14) & 0xe00) == 0x800) && (local_48 + 2 <= param_8)) &&
      (param_7[local_48] == '0')) &&
     ((param_7[local_48 + 1] == 'x' || (param_7[local_48 + 1] == 'X')))) {
    local_48 = local_48 + 2;
  }
  uVar11 = local_48;
  local_50 = *(int **)(*(int *)(param_5 + 0x30) + 4);
  (**(code **)(*local_50 + 4))(local_14);
  local_8 = 0;
  local_4c = (int *)FUN_10006410(local_54);
  local_8 = 0xffffffff;
  if ((local_50 != (int *)0x0) &&
     (puVar5 = (undefined4 *)(**(code **)(*local_50 + 8))(), puVar5 != (undefined4 *)0x0)) {
    (**(code **)*puVar5)(1);
  }
  FUN_10008b90(local_2c,param_8,0);
  local_8 = 1;
  ppppsVar8 = local_2c;
  if (7 < local_18) {
    ppppsVar8 = (short ****)local_2c[0];
  }
  (**(code **)(*local_4c + 0x2c))(param_7,param_7 + param_8,ppppsVar8);
  local_50 = *(int **)(*(int *)(param_5 + 0x30) + 4);
  (**(code **)(*local_50 + 4))();
  local_8._0_1_ = 2;
  piVar6 = (int *)FUN_10008670((int)local_54);
  local_8._0_1_ = 1;
  local_4c = piVar6;
  if ((local_50 != (int *)0x0) &&
     (puVar5 = (undefined4 *)(**(code **)(*local_50 + 8))(), puVar5 != (undefined4 *)0x0)) {
    (**(code **)*puVar5)(1);
  }
  (**(code **)(*piVar6 + 0x14))(local_44);
  local_8 = CONCAT31(local_8._1_3_,3);
  ppppcVar10 = local_44;
  if (0xf < local_30) {
    ppppcVar10 = (char ****)local_44[0];
  }
  if ((*(char *)ppppcVar10 != '\x7f') && ('\0' < *(char *)ppppcVar10)) {
    uVar7 = (**(code **)(*local_4c + 0x10))();
    local_4c = (int *)(uVar7 & 0xffff);
    cVar2 = *(char *)ppppcVar10;
    while (((cVar2 != '\x7f' && ('\0' < cVar2)) && ((uint)(int)cVar2 < param_8 - uVar11))) {
      param_8 = param_8 - (int)cVar2;
      if (local_1c < param_8) {
        FUN_10007f70();
        goto LAB_1000789d;
      }
      if (local_18 == local_1c) {
        local_50 = (int *)((uint)local_50 & 0xffffff00);
        FUN_10008930(local_2c,1,local_50,param_8,1,(short)local_4c);
      }
      else {
        ppppsVar8 = local_2c;
        if (7 < local_18) {
          ppppsVar8 = (short ****)local_2c[0];
        }
        iVar9 = local_1c - param_8;
        puVar1 = (uint *)((int)ppppsVar8 + param_8 * 2);
        local_1c = local_1c + 1;
        FUN_100301d0((uint *)((int)puVar1 + 2),puVar1,iVar9 * 2 + 2);
        *(short *)puVar1 = (short)local_4c;
        uVar11 = local_48;
      }
      if ('\0' < *(char *)((int)ppppcVar10 + 1)) {
        ppppcVar10 = (char ****)((int)ppppcVar10 + 1);
      }
      cVar2 = *(char *)ppppcVar10;
    }
  }
  local_48 = local_1c;
  uVar7 = *(uint *)(param_5 + 0x20);
  if (((*(int *)(param_5 + 0x24) < 0) || ((*(int *)(param_5 + 0x24) < 1 && (uVar7 == 0)))) ||
     (uVar7 <= local_1c)) {
    iVar9 = 0;
  }
  else {
    iVar9 = uVar7 - local_1c;
  }
  uVar7 = *(uint *)(param_5 + 0x14) & 0x1c0;
  if (uVar7 == 0x40) {
    ppppsVar8 = local_2c;
    if (7 < local_18) {
      ppppsVar8 = (short ****)local_2c[0];
    }
    puVar5 = (undefined4 *)
             FUN_10007430(param_1,(undefined4 *)local_54,param_3,param_4,(short *)ppppsVar8,uVar11);
  }
  else if (uVar7 == 0x100) {
    ppppsVar8 = local_2c;
    if (7 < local_18) {
      ppppsVar8 = (short ****)local_2c[0];
    }
    puVar5 = (undefined4 *)
             FUN_10007430(param_1,(undefined4 *)local_54,param_3,param_4,(short *)ppppsVar8,uVar11);
    puVar5 = FUN_100073b0(param_1,(undefined4 *)local_54,*puVar5,(int *)puVar5[1],param_6,iVar9);
    iVar9 = 0;
  }
  else {
    puVar5 = FUN_100073b0(param_1,(undefined4 *)local_54,param_3,param_4,param_6,iVar9);
    iVar9 = 0;
    ppppsVar8 = local_2c;
    if (7 < local_18) {
      ppppsVar8 = (short ****)local_2c[0];
    }
    puVar5 = (undefined4 *)
             FUN_10007430(param_1,(undefined4 *)local_54,*puVar5,(int *)puVar5[1],(short *)ppppsVar8
                          ,uVar11);
  }
  ppppsVar8 = local_2c;
  if (7 < local_18) {
    ppppsVar8 = (short ****)local_2c[0];
  }
  local_48 = local_48 - uVar11;
  puVar5 = (undefined4 *)
           FUN_10007430(param_1,(undefined4 *)local_54,*puVar5,(int *)puVar5[1],
                        (short *)((int)ppppsVar8 + uVar11 * 2),local_48);
  uVar3 = *puVar5;
  piVar6 = (int *)puVar5[1];
  *(undefined4 *)(param_5 + 0x20) = 0;
  *(undefined4 *)(param_5 + 0x24) = 0;
  FUN_100073b0(param_1,param_2,uVar3,piVar6,param_6,iVar9);
  if (0xf < local_30) {
    ppppcVar10 = (char ****)local_44[0];
    if ((0xfff < local_30 + 1) &&
       (ppppcVar10 = (char ****)local_44[0][-1],
       (char *)0x1f < (char *)((int)local_44[0] + (-4 - (int)ppppcVar10)))) goto LAB_1000789d;
    FUN_1002e346(ppppcVar10);
  }
  local_34 = 0;
  local_30 = 0xf;
  local_44[0] = (char ***)((uint)local_44[0] & 0xffffff00);
  if (7 < local_18) {
    ppppsVar8 = (short ****)local_2c[0];
    if ((0xfff < local_18 * 2 + 2) &&
       (ppppsVar8 = (short ****)local_2c[0][-1],
       0x1f < (uint)((int)local_2c[0] + (-4 - (int)ppppsVar8)))) {
LAB_1000789d:
      FUN_10032f7f();
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    }
    FUN_1002e346(ppppsVar8);
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100078b0 @ 100078b0