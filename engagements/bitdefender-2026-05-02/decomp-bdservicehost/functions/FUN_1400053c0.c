void FUN_1400053c0(undefined4 param_1)

{
  undefined8 *puVar1;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined4 local_48 [4];
  undefined8 local_38 [7];
  
  puVar1 = (undefined8 *)FUN_1400053a0(local_48,param_1);
  local_58 = *puVar1;
  uStack_50 = puVar1[1];
  FUN_140001e20(local_38,&local_58);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_140005400 @ 140005400