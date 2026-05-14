void __thiscall FUN_10002a00(void *this,char *param_1,char *param_2,wchar_t *param_3)

{
  int iVar1;
  wchar_t wVar2;
  mbstate_t local_18 [2];
  wchar_t local_10 [2];
  char local_c [4];
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  if (param_1 != param_2) {
    do {
      local_c[0] = *param_1;
      local_18[0] = 0;
      local_18[1] = 0;
      iVar1 = __Mbrtowc(local_10,local_c,1,local_18,(_Cvtvec *)((int)this + 0x18));
      wVar2 = local_10[0];
      if (iVar1 < 0) {
        wVar2 = L'\xffff';
      }
      param_1 = param_1 + 1;
      *param_3 = wVar2;
      param_3 = param_3 + 1;
    } while (param_1 != param_2);
  }
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002a80 @ 10002a80