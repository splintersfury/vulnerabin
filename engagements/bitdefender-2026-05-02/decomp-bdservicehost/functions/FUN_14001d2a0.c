undefined4 * FUN_14001d2a0(undefined4 *param_1)

{
  void *pvVar1;
  
  *param_1 = 0;
  *(undefined8 *)(param_1 + 2) = 0;
  *(undefined8 *)(param_1 + 4) = 0;
  pvVar1 = operator_new(0x20);
  *(void **)pvVar1 = pvVar1;
  *(void **)((longlong)pvVar1 + 8) = pvVar1;
  *(void **)(param_1 + 2) = pvVar1;
  *(ulonglong *)(param_1 + 6) = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined8 *)(param_1 + 10) = 0;
  *(undefined8 *)(param_1 + 0xc) = 7;
  *(undefined8 *)(param_1 + 0xe) = 8;
  *param_1 = 0x3f800000;
  FUN_140016fb0((ulonglong *)(param_1 + 6),0x10,*(undefined8 *)(param_1 + 2));
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d320 @ 14001d320