int FUN_1002c95f(void)

{
  int iVar1;
  int iVar2;
  LPCRITICAL_SECTION p_Var3;
  
  LOCK();
  iVar1 = DAT_10069000 + -1;
  UNLOCK();
  iVar2 = DAT_10069000;
  DAT_10069000 = iVar1;
  if (iVar1 < 0) {
    p_Var3 = (LPCRITICAL_SECTION)&DAT_1006a800;
    do {
      iVar2 = FUN_1002dbaa(p_Var3);
      p_Var3 = p_Var3 + 1;
    } while (p_Var3 != (LPCRITICAL_SECTION)&DAT_1006a8c0);
  }
  return iVar2;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002c986 @ 1002c986