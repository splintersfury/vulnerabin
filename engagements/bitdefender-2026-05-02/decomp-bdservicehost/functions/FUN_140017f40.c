void FUN_140017f40(longlong *param_1,uint param_2)

{
  uint uVar1;
  char *pcVar2;
  undefined1 auStack_58 [32];
  longlong *local_38;
  char local_1d [5];
  ulonglong local_18;
  char *pcVar3;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_58;
  pcVar2 = local_1d + 2;
  if ((int)param_2 < 0) {
    uVar1 = -param_2;
    do {
      pcVar3 = pcVar2;
      pcVar2 = pcVar3 + -1;
      *pcVar2 = (char)uVar1 + (char)((ulonglong)uVar1 / 10) * -10 + '0';
      uVar1 = (uint)((ulonglong)uVar1 / 10);
    } while (uVar1 != 0);
    pcVar2 = pcVar3 + -2;
    *pcVar2 = '-';
  }
  else {
    do {
      pcVar2 = pcVar2 + -1;
      *pcVar2 = (char)param_2 + (char)((ulonglong)param_2 / 10) * -10 + '0';
      param_2 = (uint)((ulonglong)param_2 / 10);
    } while (param_2 != 0);
  }
  param_1[3] = 0xf;
  *param_1 = 0;
  param_1[2] = 0;
  *(undefined1 *)param_1 = 0;
  local_38 = param_1;
  if (pcVar2 != local_1d + 2) {
    FUN_1400106a0(param_1,(undefined8 *)pcVar2,(ulonglong)(local_1d + (2 - (longlong)pcVar2)));
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_58);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140018020 @ 140018020

undefined1 (*) [16]
FUN_140018020(undefined1 (*param_1) [16],undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  undefined1 (*pauVar2) [16];
  
  iVar1 = FUN_14002a640("%f",param_2,param_3,param_4);
  *(undefined8 *)(param_1[1] + 8) = 0xf;
  *(undefined8 *)*param_1 = 0;
  *(undefined8 *)param_1[1] = 0;
  (*param_1)[0] = 0;
  FUN_140010530(param_1,(longlong)iVar1,0);
  pauVar2 = param_1;
  if (0xf < *(ulonglong *)(param_1[1] + 8)) {
    pauVar2 = *(undefined1 (**) [16])*param_1;
  }
  FUN_1400151d0((char *)pauVar2,(longlong)iVar1 + 1,"%f",param_2);
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400180b0 @ 1400180b0