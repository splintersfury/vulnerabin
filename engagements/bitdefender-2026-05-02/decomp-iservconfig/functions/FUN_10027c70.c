void * __fastcall FUN_10027c70(void *param_1,uint *param_2)

{
  DWORD DVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_10050490;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  DVar1 = GetLastError();
  FUN_10027ae0(param_1,DVar1,(int *)&PTR_vftable_10069ab8,param_2);
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027cd0 @ 10027cd0