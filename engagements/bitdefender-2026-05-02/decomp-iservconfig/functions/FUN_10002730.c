void __cdecl FUN_10002730(char *param_1,undefined4 param_2,_Cvtvec *param_3)

{
  char cVar1;
  code *pcVar2;
  int iVar3;
  wchar_t *pwVar4;
  char *pcVar5;
  char *pcVar6;
  int iVar7;
  uint uVar8;
  char *pcVar9;
  undefined8 local_20;
  undefined8 local_18;
  wchar_t local_10 [2];
  uint local_c;
  
  local_c = DAT_10069054 ^ (uint)&stack0xfffffffc;
  local_18 = 0;
  pcVar5 = param_1;
  do {
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  iVar7 = 0;
  pcVar5 = pcVar5 + (1 - (int)(param_1 + 1));
  pcVar9 = pcVar5;
  pcVar6 = param_1;
  while ((pcVar5 != (char *)0x0 &&
         (iVar3 = __Mbrtowc(local_10,param_1,(size_t)pcVar5,(mbstate_t *)&local_18,param_3),
         0 < iVar3))) {
    param_1 = param_1 + iVar3;
    iVar7 = iVar7 + 1;
    pcVar5 = pcVar5 + -iVar3;
  }
  uVar8 = iVar7 + 1;
  pwVar4 = (wchar_t *)FUN_1003310d(uVar8,2);
  if (pwVar4 != (wchar_t *)0x0) {
    local_20 = 0;
    while ((uVar8 != 0 &&
           (iVar7 = __Mbrtowc(pwVar4,pcVar6,(size_t)pcVar9,(mbstate_t *)&local_20,param_3),
           0 < iVar7))) {
      pcVar6 = pcVar6 + iVar7;
      pwVar4 = pwVar4 + 1;
      uVar8 = uVar8 - 1;
    }
    *pwVar4 = L'\0';
    FUN_1002e315(local_c ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_1002c81a();
  pcVar2 = (code *)swi(3);
  (*pcVar2)(pcVar9,param_3,pwVar4);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002810 @ 10002810