longlong * FUN_14000a810(longlong *param_1)

{
  short sVar1;
  short *psVar2;
  longlong lVar3;
  short *psVar4;
  ulonglong uVar5;
  
  psVar4 = (short *)&DAT_14007acd0;
  if (7 < DAT_14007ace8) {
    psVar4 = DAT_14007acd0;
  }
  if (DAT_14007ace0 == 0) {
LAB_14000a877:
    lVar3 = -1;
  }
  else {
    lVar3 = -1;
    if (DAT_14007ace0 - 1 != -1) {
      lVar3 = DAT_14007ace0 - 1;
    }
    psVar2 = psVar4 + lVar3;
    sVar1 = psVar4[lVar3];
    while (sVar1 != 0x5c) {
      if (psVar2 == psVar4) goto LAB_14000a877;
      psVar2 = psVar2 + -1;
      sVar1 = *psVar2;
    }
    lVar3 = (longlong)psVar2 - (longlong)psVar4 >> 1;
  }
  param_1[3] = 7;
  *param_1 = 0;
  param_1[2] = 0;
  *(undefined2 *)param_1 = 0;
  uVar5 = lVar3 + 1U;
  if (DAT_14007ace0 < lVar3 + 1U) {
    uVar5 = DAT_14007ace0;
  }
  psVar4 = (short *)&DAT_14007acd0;
  if (7 < DAT_14007ace8) {
    psVar4 = DAT_14007acd0;
  }
  FUN_140010340(param_1,(undefined8 *)psVar4,uVar5);
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000a8d0 @ 14000a8d0