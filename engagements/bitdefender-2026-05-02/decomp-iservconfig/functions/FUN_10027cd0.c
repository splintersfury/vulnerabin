void * __fastcall FUN_10027cd0(void *param_1,uint *param_2,undefined4 param_3,int *param_4)

{
  void *local_10;
  undefined1 *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_10050490;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_100022f0(param_1,param_2,param_3,param_4);
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027d20 @ 10027d20