int * FUN_10001890(int *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  iVar3 = DAT_1006b644;
  puVar4 = *(undefined4 **)(DAT_1006b644 + 4);
  *param_1 = (int)puVar4;
  param_1[1] = 0;
  param_1[2] = iVar3;
  if (*(char *)((int)puVar4 + 0xd) == '\0') {
    uVar1 = *param_2;
    do {
      *param_1 = (int)puVar4;
      uVar2 = puVar4[4];
      if (uVar1 <= uVar2) {
        param_1[2] = (int)puVar4;
        puVar4 = (undefined4 *)*puVar4;
      }
      else {
        puVar4 = (undefined4 *)puVar4[2];
      }
      param_1[1] = (uint)(uVar1 <= uVar2);
    } while (*(char *)((int)puVar4 + 0xd) == '\0');
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100018e0 @ 100018e0