void FUN_140005ed0(undefined8 *param_1,undefined4 param_2,undefined8 *param_3)

{
  undefined8 *puVar1;
  undefined8 local_d8;
  undefined8 uStack_d0;
  undefined4 local_c8 [4];
  longlong local_b8 [4];
  undefined8 local_98 [18];
  
  puVar1 = (undefined8 *)FUN_1400053a0(local_c8,param_2);
  local_d8 = *puVar1;
  uStack_d0 = puVar1[1];
  FUN_14000e950(local_b8,param_1);
  FUN_140005810(local_98,local_b8,param_3,&local_d8);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_98,(ThrowInfo *)&DAT_140077890);
}


// FUNCTION_END

// FUNCTION_START: FUN_140005f40 @ 140005f40