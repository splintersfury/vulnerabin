undefined4 * __thiscall FUN_10007340(void *this,undefined4 *param_1)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  
  puVar1 = *(uint **)((int)this + 8);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  *(undefined1 *)param_1 = 0;
  puVar3 = puVar1;
  do {
    uVar2 = *puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
  } while ((char)uVar2 != '\0');
  FUN_10008e70(param_1,puVar1,(int)puVar3 - ((int)puVar1 + 1));
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007390 @ 10007390