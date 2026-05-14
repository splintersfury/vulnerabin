int * __thiscall FUN_10023ea0(void *this,int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  
                    /* WARNING: Load size is inaccurate */
  iVar1 = *this;
  puVar3 = *(undefined4 **)(iVar1 + 4);
  *param_1 = (int)puVar3;
  param_1[1] = 0;
  param_1[2] = iVar1;
  if (*(char *)((int)puVar3 + 0xd) == '\0') {
    iVar1 = *param_2;
    do {
      *param_1 = (int)puVar3;
      iVar2 = puVar3[4];
      if (iVar1 <= iVar2) {
        param_1[2] = (int)puVar3;
        puVar3 = (undefined4 *)*puVar3;
      }
      else {
        puVar3 = (undefined4 *)puVar3[2];
      }
      param_1[1] = (uint)(iVar1 <= iVar2);
    } while (*(char *)((int)puVar3 + 0xd) == '\0');
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023ef0 @ 10023ef0