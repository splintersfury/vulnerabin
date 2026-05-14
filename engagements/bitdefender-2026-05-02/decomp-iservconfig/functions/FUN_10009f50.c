void FUN_10009f50(int *param_1,int param_2)

{
  int iVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_1004da40;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar1 = std::_Winerror_map(param_2);
  if (iVar1 == 0) {
    *param_1 = param_2;
    param_1[1] = (int)&PTR_vftable_10069aa8;
    ExceptionList = local_10;
    return;
  }
  *param_1 = iVar1;
  param_1[1] = (int)&PTR_vftable_10069ab0;
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10009fd0 @ 10009fd0