void FUN_140002b00(longlong param_1,wchar_t *param_2,wchar_t *param_3,char param_4,char *param_5)

{
  int iVar1;
  char cVar2;
  undefined1 auStack_68 [32];
  mbstate_t local_48 [2];
  char local_40 [8];
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_68;
  if (param_2 != param_3) {
    do {
      local_48[0] = 0;
      local_48[1] = 0;
      iVar1 = _Wcrtomb(local_40,*param_2,local_48,(_Cvtvec *)(param_1 + 0x30));
      cVar2 = local_40[0];
      if (iVar1 != 1) {
        cVar2 = param_4;
      }
      param_2 = param_2 + 1;
      *param_5 = cVar2;
      param_5 = param_5 + 1;
    } while (param_2 != param_3);
  }
  FUN_14002f160(local_38 ^ (ulonglong)auStack_68);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140002bb0 @ 140002bb0