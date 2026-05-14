undefined8 * FUN_140026df0(char *param_1,undefined8 *param_2,undefined8 *param_3,undefined8 param_4)

{
  char cVar1;
  undefined1 uVar2;
  longlong lVar3;
  longlong lVar4;
  undefined8 uVar5;
  code *pcVar6;
  longlong *plVar7;
  char *pcVar8;
  longlong *plVar9;
  undefined8 *puVar10;
  longlong *plVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  undefined1 local_b8 [8];
  undefined8 local_b0;
  undefined8 local_98 [7];
  undefined8 local_60 [7];
  
  if (param_1 != (char *)*param_3) {
    FUN_14000e950((longlong *)local_b8,(undefined8 *)"iterator does not fit current value");
    FUN_140018ed0(local_98,0xca,(undefined8 *)local_b8);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_98,(ThrowInfo *)&DAT_140077d70);
  }
  *param_2 = param_1;
  param_2[1] = 0;
  param_2[2] = 0;
  param_2[3] = 0x8000000000000000;
  pcVar8 = (char *)*param_2;
  if (*pcVar8 == '\x01') {
    param_2[1] = **(undefined8 **)(pcVar8 + 8);
  }
  else if (*pcVar8 == '\x02') {
    param_2[2] = *(undefined8 *)(*(longlong *)(pcVar8 + 8) + 8);
  }
  else {
    param_2[3] = 1;
  }
  switch(*param_1) {
  case '\x01':
    plVar9 = (longlong *)param_3[1];
    plVar11 = (longlong *)plVar9[2];
    if (*(char *)((longlong)plVar11 + 0x19) == '\0') {
      cVar1 = *(char *)(*plVar11 + 0x19);
      plVar7 = (longlong *)*plVar11;
      while (cVar1 == '\0') {
        cVar1 = *(char *)(*plVar7 + 0x19);
        plVar11 = plVar7;
        plVar7 = (longlong *)*plVar7;
      }
    }
    else {
      cVar1 = *(char *)(plVar9[1] + 0x19);
      plVar7 = plVar9;
      plVar11 = (longlong *)plVar9[1];
      while ((cVar1 == '\0' && (plVar7 == (longlong *)plVar11[2]))) {
        cVar1 = *(char *)(plVar11[1] + 0x19);
        plVar7 = plVar11;
        plVar11 = (longlong *)plVar11[1];
      }
    }
    plVar9 = FUN_140029f50(*(longlong **)(param_1 + 8),plVar9);
    FUN_140029e10(plVar9 + 4);
    FUN_14002f180();
    param_2[1] = plVar11;
    break;
  case '\x02':
    lVar3 = param_3[2];
    lVar4 = *(longlong *)(param_1 + 8);
    puVar13 = *(undefined1 **)(lVar4 + 8);
    puVar12 = (undefined1 *)(lVar3 + 0x10);
    if (puVar12 != puVar13) {
      do {
        uVar2 = *puVar12;
        uVar5 = *(undefined8 *)(puVar12 + 8);
        *puVar12 = 0;
        *(undefined8 *)(puVar12 + 8) = 0;
        local_b8[0] = puVar12[-0x10];
        puVar12[-0x10] = uVar2;
        local_b0 = *(undefined8 *)(puVar12 + -8);
        *(undefined8 *)(puVar12 + -8) = uVar5;
        FUN_14001cf70(local_b8);
        puVar12 = puVar12 + 0x10;
      } while (puVar12 != puVar13);
      puVar13 = *(undefined1 **)(lVar4 + 8);
    }
    FUN_14001cf70(puVar13 + -0x10);
    *(longlong *)(lVar4 + 8) = *(longlong *)(lVar4 + 8) + -0x10;
    param_2[2] = lVar3;
    break;
  case '\x03':
  case '\x04':
  case '\x05':
  case '\x06':
  case '\a':
    if (param_3[3] != 0) {
      FUN_14000e950((longlong *)local_b8,(undefined8 *)"iterator out of range");
      FUN_140018ed0(local_98,0xcd,(undefined8 *)local_b8);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_98,(ThrowInfo *)&DAT_140077d70);
    }
    if (*param_1 == '\x03') {
      plVar9 = *(longlong **)(param_1 + 8);
      if (0xf < (ulonglong)plVar9[3]) {
        if ((0xfff < plVar9[3] + 1U) && (0x1f < (*plVar9 - *(longlong *)(*plVar9 + -8)) - 8U)) {
          FUN_140035d28();
          pcVar6 = (code *)swi(3);
          puVar10 = (undefined8 *)(*pcVar6)();
          return puVar10;
        }
        FUN_14002f180();
      }
      plVar9[2] = 0;
      plVar9[3] = 0xf;
      *(undefined1 *)plVar9 = 0;
      FUN_14002f180();
      param_1[8] = '\0';
      param_1[9] = '\0';
      param_1[10] = '\0';
      param_1[0xb] = '\0';
      param_1[0xc] = '\0';
      param_1[0xd] = '\0';
      param_1[0xe] = '\0';
      param_1[0xf] = '\0';
    }
    *param_1 = '\0';
    break;
  default:
    pcVar8 = FUN_14001ddd0(param_1);
    plVar9 = FUN_14000e950((longlong *)local_b8,(undefined8 *)pcVar8);
    puVar10 = FUN_140011fa0(local_98,(undefined8 *)"cannot use erase() with ",plVar9,param_4);
    FUN_1400190c0(local_60,0x133,puVar10);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_60,(ThrowInfo *)&DAT_140077cc0);
  }
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400270e0 @ 1400270e0