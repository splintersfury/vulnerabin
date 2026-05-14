void * __fastcall FUN_1002c1c0(void *param_1,undefined4 param_2)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004da40;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_10027ae0(param_1,param_2,(int *)&PTR_vftable_10069ab8,
               (uint *)"IWbemServices::ExecQuery failed");
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c210 @ 1002c210