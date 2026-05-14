void FUN_1400029d0(longlong param_1,char *param_2,char *param_3,wchar_t *param_4)

{
  int iVar1;
  wchar_t wVar2;
  undefined1 auStackY_78 [32];
  char local_48 [8];
  wchar_t local_40 [4];
  mbstate_t local_38 [2];
  ulonglong local_30;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStackY_78;
  if (param_2 != param_3) {
    do {
      local_48[0] = *param_2;
      local_38[0] = 0;
      local_38[1] = 0;
      iVar1 = _Mbrtowc(local_40,local_48,1,local_38,(_Cvtvec *)(param_1 + 0x30));
      wVar2 = local_40[0];
      if (iVar1 < 0) {
        wVar2 = L'\xffff';
      }
      param_2 = param_2 + 1;
      *param_4 = wVar2;
      param_4 = param_4 + 1;
    } while (param_2 != param_3);
  }
  FUN_14002f160(local_30 ^ (ulonglong)auStackY_78);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002aa0 @ 140002aa0