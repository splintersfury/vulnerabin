void __fastcall FUN_10023e40(undefined4 *param_1)

{
  undefined1 auStack_14 [4];
  undefined4 *local_10;
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)auStack_14;
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 7;
  *(undefined2 *)param_1 = 0;
  local_10 = param_1;
  FUN_10001d40(param_1,(uint *)L"settings\\ProductAgent.json",0x1a);
  FUN_1002e315(local_c ^ (uint)auStack_14);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10023ea0 @ 10023ea0