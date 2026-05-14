void FUN_1001bd50(undefined1 *param_1,undefined8 *param_2)

{
  undefined4 local_10;
  undefined4 uStack_c;
  
  local_10 = (undefined4)*param_2;
  uStack_c = (undefined4)((ulonglong)*param_2 >> 0x20);
  *param_1 = 7;
  *(undefined4 *)(param_1 + 8) = local_10;
  *(undefined4 *)(param_1 + 0xc) = uStack_c;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001bd80 @ 1001bd80