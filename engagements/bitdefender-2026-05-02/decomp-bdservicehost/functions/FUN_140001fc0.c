void FUN_140001fc0(void)

{
  undefined8 *puVar1;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined4 local_48 [4];
  undefined8 local_38 [7];
  
  puVar1 = (undefined8 *)FUN_140001be0(local_48);
  local_58 = *puVar1;
  uStack_50 = puVar1[1];
  FUN_140001e20(local_38,&local_58);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_38,(ThrowInfo *)&DAT_140077a60);
}


// FUNCTION_END

// FUNCTION_START: FUN_140002000 @ 140002000