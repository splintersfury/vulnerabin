void FUN_1400024c0(char *param_1,undefined8 param_2,_Cvtvec *param_3)

{
  code *pcVar1;
  int iVar2;
  wchar_t *pwVar3;
  longlong lVar4;
  ulonglong uVar5;
  size_t sVar6;
  longlong lVar7;
  size_t sVar9;
  char *pcVar10;
  undefined1 auStackY_78 [32];
  wchar_t local_48 [4];
  undefined8 local_40;
  undefined8 local_38;
  ulonglong local_30;
  longlong lVar8;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStackY_78;
  lVar4 = 0;
  local_40 = 0;
  lVar7 = -1;
  do {
    lVar8 = lVar7;
    lVar7 = lVar8 + 1;
  } while (param_1[lVar7] != '\0');
  sVar9 = lVar8 + 2;
  sVar6 = sVar9;
  pcVar10 = param_1;
  while ((sVar6 != 0 &&
         (iVar2 = _Mbrtowc(local_48,pcVar10,sVar6,(mbstate_t *)&local_40,param_3), 0 < iVar2))) {
    lVar4 = lVar4 + 1;
    pcVar10 = pcVar10 + iVar2;
    sVar6 = sVar6 - (longlong)iVar2;
  }
  uVar5 = lVar4 + 1;
  pwVar3 = (wchar_t *)_calloc_base(uVar5,2);
  if (pwVar3 != (wchar_t *)0x0) {
    local_38 = 0;
    while ((uVar5 != 0 &&
           (iVar2 = _Mbrtowc(pwVar3,param_1,sVar9,(mbstate_t *)&local_38,param_3), 0 < iVar2))) {
      pwVar3 = pwVar3 + 1;
      param_1 = param_1 + iVar2;
      uVar5 = uVar5 - 1;
    }
    *pwVar3 = L'\0';
    FUN_14002f160(local_30 ^ (ulonglong)auStackY_78);
    return;
  }
  FUN_14002d6b4();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400025d0 @ 1400025d0