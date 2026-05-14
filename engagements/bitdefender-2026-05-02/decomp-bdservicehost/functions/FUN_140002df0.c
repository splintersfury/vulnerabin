longlong FUN_140002df0(longlong param_1)

{
  *(uint *)(param_1 + 0x18) = *(uint *)(param_1 + 0x18) & 0xfffff9ff;
  *(uint *)(param_1 + 0x18) = *(uint *)(param_1 + 0x18) | 0x800;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002e10 @ 140002e10