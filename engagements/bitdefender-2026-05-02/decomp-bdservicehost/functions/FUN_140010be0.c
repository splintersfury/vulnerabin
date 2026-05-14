longlong * FUN_140010be0(longlong param_1,longlong *param_2)

{
  undefined8 *puVar1;
  ulonglong uVar2;
  
  puVar1 = *(undefined8 **)(param_1 + 0x10);
  uVar2 = 0xffffffffffffffff;
  *param_2 = 0;
  param_2[2] = 0;
  param_2[3] = 0xf;
  *(undefined1 *)param_2 = 0;
  do {
    uVar2 = uVar2 + 1;
  } while (*(char *)((longlong)puVar1 + uVar2) != '\0');
  FUN_1400106a0(param_2,puVar1,uVar2);
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140010c30 @ 140010c30