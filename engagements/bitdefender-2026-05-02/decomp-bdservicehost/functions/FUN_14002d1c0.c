longlong FUN_14002d1c0(longlong param_1)

{
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  
  if (*(char *)(param_1 + 0x30) != '\0') {
    return param_1;
  }
  local_28 = 0;
  uStack_20 = 0;
  local_18 = 0;
  FUN_14000ec80(&local_28);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(&local_28,(ThrowInfo *)&DAT_1400777e0);
}


// FUNCTION_END

// FUNCTION_START: FUN_14002d200 @ 14002d200