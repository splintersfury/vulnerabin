undefined8 FUN_140008d20(DWORD *param_1)

{
  if (param_1 != (DWORD *)0x0) {
    Sleep(*param_1);
  }
  DAT_00000000 = DAT_00000000 + '\x01';
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008d50 @ 140008d50