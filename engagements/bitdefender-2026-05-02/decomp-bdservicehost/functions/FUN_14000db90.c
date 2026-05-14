short FUN_14000db90(longlong param_1,short param_2)

{
  ulonglong uVar1;
  
  uVar1 = **(ulonglong **)(param_1 + 0x38);
  if (((uVar1 != 0) && (**(ulonglong **)(param_1 + 0x18) < uVar1)) &&
     ((param_2 == -1 ||
      ((param_2 == *(short *)(uVar1 - 2) || ((*(byte *)(param_1 + 0x70) & 2) == 0)))))) {
    **(int **)(param_1 + 0x50) = **(int **)(param_1 + 0x50) + 1;
    **(longlong **)(param_1 + 0x38) = **(longlong **)(param_1 + 0x38) + -2;
    if (param_2 != -1) {
      *(short *)**(undefined8 **)(param_1 + 0x38) = param_2;
    }
    if (param_2 == -1) {
      param_2 = 0;
    }
    return param_2;
  }
  return -1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000dbf0 @ 14000dbf0