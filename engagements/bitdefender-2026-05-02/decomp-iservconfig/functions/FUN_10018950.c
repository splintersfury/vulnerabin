void __fastcall FUN_10018950(undefined4 *param_1,uint *param_2)

{
  uint uVar1;
  undefined1 auStack_14 [4];
  undefined4 *local_10;
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_14;
  uVar1 = param_2[4];
  if (7 < param_2[5]) {
    param_2 = (uint *)*param_2;
  }
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  local_10 = param_1;
  FUN_10001d40(param_1,param_2,uVar1);
  FUN_1002e315(local_c ^ (uint)auStack_14);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100189b0 @ 100189b0