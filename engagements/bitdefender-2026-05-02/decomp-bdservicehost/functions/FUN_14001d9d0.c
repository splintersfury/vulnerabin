longlong * FUN_14001d9d0(longlong *param_1)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 uVar3;
  char cVar4;
  int iVar5;
  longlong *plVar6;
  
  if (param_1[0x10] != 0) {
    if (*(longlong **)param_1[3] == param_1 + 0xe) {
      lVar1 = param_1[0x11];
      lVar2 = param_1[0x12];
      *(longlong *)param_1[3] = lVar1;
      *(longlong *)param_1[7] = lVar1;
      *(int *)param_1[10] = (int)lVar2 - (int)lVar1;
    }
    cVar4 = FUN_14001d7d0(param_1);
    plVar6 = param_1;
    if (cVar4 == '\0') {
      plVar6 = (longlong *)0x0;
    }
    iVar5 = fclose((FILE *)param_1[0x10]);
    if (iVar5 == 0) goto LAB_14001da45;
  }
  plVar6 = (longlong *)0x0;
LAB_14001da45:
  *(undefined1 *)((longlong)param_1 + 0x7c) = 0;
  param_1[0xb] = (longlong)param_1 + 0x4c;
  param_1[3] = (longlong)(param_1 + 1);
  param_1[4] = (longlong)(param_1 + 2);
  param_1[7] = (longlong)(param_1 + 5);
  param_1[8] = (longlong)(param_1 + 6);
  param_1[10] = (longlong)(param_1 + 9);
  *(undefined1 *)((longlong)param_1 + 0x71) = 0;
  param_1[2] = 0;
  param_1[6] = 0;
  *(undefined4 *)((longlong)param_1 + 0x4c) = 0;
  uVar3 = DAT_14007d658;
  param_1[1] = 0;
  param_1[5] = 0;
  *(undefined4 *)(param_1 + 9) = 0;
  param_1[0x10] = 0;
  *(undefined8 *)((longlong)param_1 + 0x74) = uVar3;
  param_1[0xd] = 0;
  return plVar6;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001dac0 @ 14001dac0