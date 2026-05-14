void __fastcall FUN_10028720(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  uint uStack_198;
  undefined8 local_28;
  undefined4 local_20;
  uint local_1c;
  undefined1 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100506a3;
  local_10 = ExceptionList;
  uStack_198 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_14 = (undefined1 *)&uStack_198;
  ExceptionList = &local_10;
  local_8 = 0;
  *param_3 = 0;
  param_3[1] = &PTR_vftable_10069aa8;
  local_28 = 0;
  local_20 = 0;
  local_1c = uStack_198;
  FUN_100282a0(&local_28,param_2);
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_10028510(param_1,(BYTE *)local_28,local_28._4_4_);
  if ((BYTE *)local_28 != (BYTE *)0x0) {
    thunk_FUN_100330ca((BYTE *)local_28);
  }
  FUN_100288a9();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch@100287b5 @ 100287b5