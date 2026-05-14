void __thiscall
FUN_10006ec0(void *this,undefined4 *param_1,undefined4 param_2,int *param_3,int param_4,
            ushort param_5,char param_6)

{
  uint uVar1;
  undefined4 uVar2;
  code *pcVar3;
  int *piVar4;
  undefined4 *puVar5;
  short ****ppppsVar6;
  void *pvVar7;
  int iVar8;
  void *local_54 [5];
  uint local_40;
  undefined4 local_3c;
  int *local_38;
  uint local_34;
  void *local_30;
  short ***local_2c [4];
  uint local_1c;
  uint local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004dee5;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_34 = (uint)param_5;
  local_30 = this;
  if ((*(uint *)(param_4 + 0x14) & 0x4000) == 0) {
                    /* WARNING: Load size is inaccurate */
    (**(code **)(*this + 0x24))(param_1,param_2,param_3,param_4,local_34,param_6);
  }
  else {
    local_38 = *(int **)(*(int *)(param_4 + 0x30) + 4);
    (**(code **)(*local_38 + 4))(local_14);
    local_8 = 0;
    piVar4 = (int *)FUN_10008670((int)&local_3c);
    if ((local_38 != (int *)0x0) &&
       (puVar5 = (undefined4 *)(**(code **)(*local_38 + 8))(), puVar5 != (undefined4 *)0x0)) {
      (**(code **)*puVar5)(1);
    }
    local_1c = 0;
    local_18 = 7;
    local_2c[0] = (short ***)0x0;
    local_8 = 1;
    if (param_6 == '\0') {
      (**(code **)(*piVar4 + 0x18))(local_54);
    }
    else {
      (**(code **)(*piVar4 + 0x1c))();
    }
    FUN_10005380(local_2c,(int *)local_54);
    if (7 < local_40) {
      pvVar7 = local_54[0];
      if ((0xfff < local_40 * 2 + 2) &&
         (pvVar7 = *(void **)((int)local_54[0] + -4),
         0x1f < (uint)((int)local_54[0] + (-4 - (int)pvVar7)))) goto LAB_100070ce;
      FUN_1002e346(pvVar7);
    }
    uVar1 = *(uint *)(param_4 + 0x20);
    if ((*(int *)(param_4 + 0x24) < 0) ||
       (((*(int *)(param_4 + 0x24) < 1 && (uVar1 == 0)) || (uVar1 <= local_1c)))) {
      iVar8 = 0;
    }
    else {
      iVar8 = uVar1 - local_1c;
    }
    if ((*(uint *)(param_4 + 0x14) & 0x1c0) != 0x40) {
      puVar5 = FUN_100073b0(local_30,&local_3c,param_2,param_3,local_34,iVar8);
      iVar8 = 0;
      param_2 = *puVar5;
      param_3 = (int *)puVar5[1];
    }
    ppppsVar6 = local_2c;
    if (7 < local_18) {
      ppppsVar6 = (short ****)local_2c[0];
    }
    puVar5 = (undefined4 *)
             FUN_10007430(local_30,&local_3c,param_2,param_3,(short *)ppppsVar6,local_1c);
    uVar2 = *puVar5;
    piVar4 = (int *)puVar5[1];
    *(undefined4 *)(param_4 + 0x20) = 0;
    *(undefined4 *)(param_4 + 0x24) = 0;
    FUN_100073b0(local_30,param_1,uVar2,piVar4,local_34,iVar8);
    if (7 < local_18) {
      ppppsVar6 = (short ****)local_2c[0];
      if ((0xfff < local_18 * 2 + 2) &&
         (ppppsVar6 = (short ****)local_2c[0][-1],
         0x1f < (uint)((int)local_2c[0] + (-4 - (int)ppppsVar6)))) {
LAB_100070ce:
        FUN_10032f7f();
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_1002e346(ppppsVar6);
    }
  }
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100070e0 @ 100070e0