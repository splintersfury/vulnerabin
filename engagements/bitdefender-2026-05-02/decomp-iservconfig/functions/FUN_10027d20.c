void __fastcall FUN_10027d20(HCRYPTPROV *param_1)

{
  if (*param_1 != 0) {
    CryptReleaseContext(*param_1,0);
    *param_1 = 0;
  }
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10027d40 @ 10027d40