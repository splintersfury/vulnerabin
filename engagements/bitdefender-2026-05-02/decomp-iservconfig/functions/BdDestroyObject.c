void __cdecl BdDestroyObject(uint *param_1,undefined4 param_2)

{
  code *pcVar1;
  uint uVar2;
  int *this;
  uint *puVar3;
  void *pvVar4;
  undefined1 auStack_2c [4];
  void *local_28 [4];
  undefined4 local_18;
  uint local_14;
  int local_10;
  uint local_c;
  
                    /* 0x9300  2  BdDestroyObject */
  this = DAT_1006b6a8;
  local_c = DAT_10069054 ^ (uint)auStack_2c;
  local_10 = 0;
  local_28[0] = (void *)0x0;
  local_18 = 0;
  local_14 = 7;
  puVar3 = param_1;
  do {
    uVar2 = *puVar3;
    puVar3 = (uint *)((int)puVar3 + 2);
  } while ((short)uVar2 != 0);
  FUN_10001d40(local_28,param_1,(int)puVar3 - ((int)param_1 + 2) >> 1);
  FUN_10009750(this,&local_10,(ushort *)local_28);
  if (7 < local_14) {
    pvVar4 = local_28[0];
    if (0xfff < local_14 * 2 + 2) {
      pvVar4 = *(void **)((int)local_28[0] + -4);
      if (0x1f < (uint)((int)local_28[0] + (-4 - (int)pvVar4))) {
        FUN_10032f7f();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
    }
    FUN_1002e346(pvVar4);
  }
  if (local_10 != *this) {
    (**(code **)(**(int **)(local_10 + 0x28) + 0x10))(param_2);
  }
  FUN_10009690(DAT_1006b6a8);
  FUN_1002e315(local_c ^ (uint)auStack_2c);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100093f0 @ 100093f0