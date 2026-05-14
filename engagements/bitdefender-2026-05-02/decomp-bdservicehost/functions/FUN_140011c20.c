void FUN_140011c20(longlong *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)*param_1;
  *(undefined8 *)puVar1[1] = 0;
  puVar1 = (undefined8 *)*puVar1;
  while (puVar1 != (undefined8 *)0x0) {
    puVar1 = (undefined8 *)*puVar1;
    FUN_14002f180();
  }
  FUN_14002f180();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140011c80 @ 140011c80