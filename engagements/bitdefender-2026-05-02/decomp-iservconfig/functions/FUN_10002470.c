undefined4 * FUN_10002470(undefined4 *param_1,int param_2)

{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  
  if (param_2 == 1) {
    *param_1 = 0;
    param_1[4] = 0;
    param_1[5] = 0xf;
    *(undefined1 *)param_1 = 0;
    FUN_10008e70(param_1,(uint *)"iostream stream error",0x15);
    return param_1;
  }
  puVar2 = (uint *)std::_Syserror_map(param_2);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0xf;
  *(undefined1 *)param_1 = 0;
  puVar3 = puVar2;
  do {
    uVar1 = *puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
  } while ((char)uVar1 != '\0');
  FUN_10008e70(param_1,puVar2,(int)puVar3 - ((int)puVar2 + 1));
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_100024f0 @ 100024f0