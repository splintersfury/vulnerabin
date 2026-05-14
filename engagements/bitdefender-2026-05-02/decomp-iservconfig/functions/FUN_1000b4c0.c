uint __fastcall FUN_1000b4c0(int param_1)

{
  byte *pbVar1;
  
  pbVar1 = *(byte **)(param_1 + 4);
  if (pbVar1 < *(byte **)(param_1 + 8)) {
    *(byte **)(param_1 + 4) = pbVar1 + 1;
    return (uint)*pbVar1;
  }
  return 0xffffffff;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000b4e0 @ 1000b4e0