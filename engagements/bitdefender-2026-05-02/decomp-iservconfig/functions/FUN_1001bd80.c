void FUN_1001bd80(undefined1 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  uVar1 = *param_2;
  uVar2 = param_2[1];
  *param_1 = 6;
  *(undefined4 *)(param_1 + 8) = uVar1;
  *(undefined4 *)(param_1 + 0xc) = uVar2;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001bda0 @ 1001bda0