void __fastcall FUN_10027e20(HCRYPTHASH *param_1)

{
  if (*param_1 != 0) {
    CryptDestroyHash(*param_1);
    *param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027e40 @ 10027e40