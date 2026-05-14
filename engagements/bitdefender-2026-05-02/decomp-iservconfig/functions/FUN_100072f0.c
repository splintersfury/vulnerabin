undefined4 * __thiscall FUN_100072f0(void *this,undefined4 *param_1)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  
  puVar1 = *(uint **)((int)this + 0x10);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  puVar3 = puVar1;
  do {
    uVar2 = *puVar3;
    puVar3 = (uint *)((int)puVar3 + 2);
  } while ((short)uVar2 != 0);
  FUN_10001d40(param_1,puVar1,(int)puVar3 - ((int)puVar1 + 2) >> 1);
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10007340 @ 10007340