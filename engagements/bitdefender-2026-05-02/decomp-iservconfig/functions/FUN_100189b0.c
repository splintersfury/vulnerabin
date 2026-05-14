void __fastcall FUN_100189b0(undefined4 *param_1)

{
  undefined *puVar1;
  short sVar2;
  undefined *puVar3;
  short *psVar4;
  undefined4 *local_10;
  uint local_c;
  
  puVar3 = PTR_DAT_1005e800;
  local_c = DAT_10069054 ^ (uint)&local_10;
  puVar1 = PTR_DAT_1005e800 + 2;
  psVar4 = (short *)PTR_DAT_1005e800;
  do {
    sVar2 = *psVar4;
    psVar4 = psVar4 + 1;
  } while (sVar2 != 0);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  local_10 = param_1;
  FUN_10001d40(param_1,(uint *)puVar3,(int)psVar4 - (int)puVar1 >> 1);
  FUN_1002e315(local_c ^ (uint)&local_10);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018a30 @ 10018a30