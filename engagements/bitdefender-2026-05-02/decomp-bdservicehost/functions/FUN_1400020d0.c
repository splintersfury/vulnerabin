longlong * FUN_1400020d0(undefined8 param_1,longlong *param_2,int param_3)

{
  char *pcVar1;
  ulonglong uVar2;
  
  pcVar1 = FUN_14002d7d0(param_3);
  param_2[3] = 0xf;
  *param_2 = 0;
  uVar2 = 0xffffffffffffffff;
  param_2[2] = 0;
  *(undefined1 *)param_2 = 0;
  do {
    uVar2 = uVar2 + 1;
  } while (pcVar1[uVar2] != '\0');
  FUN_1400106a0(param_2,(undefined8 *)pcVar1,uVar2);
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002120 @ 140002120