LPSTR FUN_1400120c0(LPSTR param_1,UINT param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  LPCWSTR pWVar2;
  code *pcVar3;
  int iVar4;
  undefined8 uVar5;
  LPSTR pCVar6;
  
  param_1[0] = '\0';
  param_1[1] = '\0';
  param_1[2] = '\0';
  param_1[3] = '\0';
  param_1[4] = '\0';
  param_1[5] = '\0';
  param_1[6] = '\0';
  param_1[7] = '\0';
  param_1[0x10] = '\0';
  param_1[0x11] = '\0';
  param_1[0x12] = '\0';
  param_1[0x13] = '\0';
  param_1[0x14] = '\0';
  param_1[0x15] = '\0';
  param_1[0x16] = '\0';
  param_1[0x17] = '\0';
  param_1[0x18] = '\x0f';
  param_1[0x19] = '\0';
  param_1[0x1a] = '\0';
  param_1[0x1b] = '\0';
  param_1[0x1c] = '\0';
  param_1[0x1d] = '\0';
  param_1[0x1e] = '\0';
  param_1[0x1f] = '\0';
  *param_1 = '\0';
  uVar1 = param_3[1];
  if (uVar1 != 0) {
    if (0x7fffffff < uVar1) {
      FUN_140001fc0();
      pcVar3 = (code *)swi(3);
      pCVar6 = (LPSTR)(*pcVar3)();
      return pCVar6;
    }
    pWVar2 = (LPCWSTR)*param_3;
    uVar5 = FUN_14002e3c0(param_2,pWVar2,(int)uVar1,(LPSTR)0x0,0);
    iVar4 = (int)((ulonglong)uVar5 >> 0x20);
    if (iVar4 != 0) {
      FUN_1400053c0(iVar4);
      pcVar3 = (code *)swi(3);
      pCVar6 = (LPSTR)(*pcVar3)();
      return pCVar6;
    }
    FUN_14000e850((undefined8 *)param_1,(longlong)(int)uVar5,0);
    pCVar6 = param_1;
    if (0xf < *(ulonglong *)(param_1 + 0x18)) {
      pCVar6 = *(LPSTR *)param_1;
    }
    uVar5 = FUN_14002e3c0(param_2,pWVar2,(int)uVar1,pCVar6,(int)uVar5);
    iVar4 = (int)((ulonglong)uVar5 >> 0x20);
    if (iVar4 != 0) {
      FUN_1400053c0(iVar4);
      pcVar3 = (code *)swi(3);
      pCVar6 = (LPSTR)(*pcVar3)();
      return pCVar6;
    }
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_140012190 @ 140012190