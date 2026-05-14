void __cdecl
BdCreateObject(uint *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
              undefined4 param_5,undefined4 *param_6)

{
  code *pcVar1;
  uint uVar2;
  int *this;
  int iVar3;
  uint *puVar4;
  void *pvVar5;
  undefined1 auStack_3c [4];
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  void *local_28 [2];
  uint uStack_20;
  undefined4 local_18;
  uint local_14;
  int local_10;
  uint local_c;
  
                    /* 0x9160  1  BdCreateObject */
  local_c = DAT_10069054 ^ (uint)auStack_3c;
  if ((param_6 == (undefined4 *)0x0) || (*param_6 = 0, param_1 == (uint *)0x0)) {
    FUN_1002e315(local_c ^ (uint)auStack_3c);
    return;
  }
  iVar3 = FUN_100093f0(DAT_1006b6a8);
  this = DAT_1006b6a8;
  if (iVar3 != 0) {
    FUN_1002e315(local_c ^ (uint)auStack_3c);
    return;
  }
  local_38 = param_2;
  local_34 = param_3;
  local_30 = param_4;
  local_2c = param_5;
  local_10 = 0;
  local_28[0] = (void *)0x0;
  local_18 = 0;
  local_14 = 7;
  puVar4 = param_1;
  do {
    uVar2 = *puVar4;
    puVar4 = (uint *)((int)puVar4 + 2);
  } while ((short)uVar2 != 0);
  FUN_10001d40(local_28,param_1,(int)puVar4 - ((int)param_1 + 2) >> 1);
  FUN_10009750(this,&local_10,(ushort *)local_28);
  if (7 < local_14) {
    pvVar5 = local_28[0];
    if (0xfff < local_14 * 2 + 2) {
      pvVar5 = *(void **)((int)local_28[0] + -4);
      if (0x1f < (uint)((int)local_28[0] + (-4 - (int)pvVar5))) {
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
    FUN_1002e346(pvVar5);
  }
  if (local_10 == *this) {
    FUN_10009690(DAT_1006b6a8);
    FUN_1002e315(local_c ^ (uint)auStack_3c);
    return;
  }
  iVar3 = (**(code **)(**(int **)(local_10 + 0x28) + 0xc))(local_38,local_34,local_30);
  if (iVar3 != 0) {
    FUN_10009690(DAT_1006b6a8);
  }
  FUN_1002e315(uStack_20 ^ (uint)&stack0xffffffb0);
  return;
}


// FUNCTION_END

// FUNCTION_START: BdDestroyObject @ 10009300