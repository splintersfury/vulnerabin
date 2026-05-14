HICON __fastcall FUN_1000cf70(int param_1)

{
  code *pcVar1;
  int iVar2;
  HICON pHVar3;
  
  iVar2 = __Mtx_lock((_Mtx_internal_imp_t *)(param_1 + 4));
  if (iVar2 == 0) {
    pHVar3 = *(HICON *)(param_1 + 0x34);
    if (pHVar3 == (HICON)0x0) {
      pHVar3 = LoadIconW((HINSTANCE)&IMAGE_DOS_HEADER_10000000,(LPCWSTR)0x65);
      *(HICON *)(param_1 + 0x34) = pHVar3;
    }
    __Mtx_unlock(param_1 + 4);
    return pHVar3;
  }
  FUN_1002d2dd(iVar2);
  pcVar1 = (code *)swi(3);
  pHVar3 = (HICON)(*pcVar1)();
  return pHVar3;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000cfc0 @ 1000cfc0