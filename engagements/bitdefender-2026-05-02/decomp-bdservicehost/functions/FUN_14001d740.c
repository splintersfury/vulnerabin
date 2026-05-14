void FUN_14001d740(longlong param_1,longlong *param_2)

{
  char cVar1;
  
  cVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_2);
  if (cVar1 != '\0') {
    *(undefined8 *)(param_1 + 0x68) = 0;
    return;
  }
  *(longlong **)(param_1 + 0x68) = param_2;
  *(undefined8 **)(param_1 + 0x18) = (undefined8 *)(param_1 + 8);
  *(undefined8 **)(param_1 + 0x20) = (undefined8 *)(param_1 + 0x10);
  *(undefined8 **)(param_1 + 0x38) = (undefined8 *)(param_1 + 0x28);
  *(undefined8 **)(param_1 + 0x40) = (undefined8 *)(param_1 + 0x30);
  *(undefined4 **)(param_1 + 0x50) = (undefined4 *)(param_1 + 0x48);
  *(undefined4 **)(param_1 + 0x58) = (undefined4 *)(param_1 + 0x4c);
  *(undefined8 *)(param_1 + 0x10) = 0;
  *(undefined8 *)(param_1 + 0x30) = 0;
  *(undefined4 *)(param_1 + 0x4c) = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined8 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0x48) = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d7d0 @ 14001d7d0