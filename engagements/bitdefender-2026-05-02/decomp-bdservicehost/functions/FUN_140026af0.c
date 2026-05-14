void FUN_140026af0(longlong *param_1,undefined1 *param_2,char *param_3)

{
  longlong lVar1;
  uint uVar2;
  ulonglong uVar3;
  char *pcVar4;
  longlong *plVar5;
  code *pcVar6;
  char cVar7;
  longlong lVar8;
  ulonglong uVar9;
  undefined1 auStack_68 [32];
  char local_48 [8];
  undefined8 local_40;
  char local_38 [8];
  longlong *local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_68;
  uVar3 = param_1[7];
  if (((longlong)uVar3 < 0) && (uVar3 != 0)) {
    lVar8 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    lVar8 = (uVar3 >> 5) * 4;
  }
  uVar9 = (ulonglong)((uint)uVar3 & 0x1f);
  uVar3 = uVar9 - 1;
  if (uVar9 == 0) {
    lVar1 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    lVar1 = (uVar3 >> 5) * 4;
  }
  if ((*(uint *)(param_1[4] + lVar8 + lVar1) >> ((byte)uVar3 & 0x1f) & 1) == 0) {
    *param_2 = 0;
    *(undefined8 *)(param_2 + 8) = 0;
    goto LAB_140026dbf;
  }
  FUN_14001de50(local_38,*param_3);
  plVar5 = local_30;
  cVar7 = local_38[0];
  if (param_1[1] == param_1[2]) {
    local_38[0] = '\0';
    local_30 = (longlong *)0x0;
    pcVar4 = (char *)*param_1;
    local_48[0] = *pcVar4;
    *pcVar4 = cVar7;
    local_40 = *(undefined8 *)(pcVar4 + 8);
    *(longlong **)(pcVar4 + 8) = plVar5;
    FUN_14001cf70(local_48);
    lVar8 = *param_1;
LAB_140026bf3:
    *param_2 = 1;
LAB_140026bf6:
    *(longlong *)(param_2 + 8) = lVar8;
  }
  else {
    pcVar4 = *(char **)(param_1[2] + -8);
    if (pcVar4 != (char *)0x0) {
      if (*pcVar4 == '\x02') {
        plVar5 = *(longlong **)(pcVar4 + 8);
        pcVar4 = (char *)plVar5[1];
        if (pcVar4 == (char *)plVar5[2]) {
          FUN_140029c40(plVar5,pcVar4,local_38);
        }
        else {
          *pcVar4 = local_38[0];
          *(longlong **)(pcVar4 + 8) = local_30;
          local_38[0] = '\0';
          local_30 = (longlong *)0x0;
          plVar5[1] = plVar5[1] + 0x10;
        }
        lVar8 = *(longlong *)(*(longlong *)(*(longlong *)(param_1[2] + -8) + 8) + 8) + -0x10;
        goto LAB_140026bf3;
      }
      uVar3 = param_1[0xb];
      if (((longlong)uVar3 < 0) && (uVar3 != 0)) {
        lVar8 = -((~uVar3 >> 5) * 4 + 4);
      }
      else {
        lVar8 = (uVar3 >> 5) * 4;
      }
      uVar9 = (ulonglong)((uint)uVar3 & 0x1f);
      uVar3 = uVar9 - 1;
      if (uVar9 == 0) {
        lVar1 = -((~uVar3 >> 5) * 4 + 4);
      }
      else {
        lVar1 = (uVar3 >> 5) * 4;
      }
      uVar2 = *(uint *)(param_1[8] + lVar8 + lVar1);
      FUN_140025870(param_1 + 8);
      plVar5 = local_30;
      cVar7 = local_38[0];
      if ((uVar2 >> ((byte)uVar3 & 0x1f) & 1) == 0) goto LAB_140026c88;
      local_38[0] = '\0';
      local_30 = (longlong *)0x0;
      pcVar4 = (char *)param_1[0xc];
      local_48[0] = *pcVar4;
      *pcVar4 = cVar7;
      local_40 = *(undefined8 *)(pcVar4 + 8);
      *(longlong **)(pcVar4 + 8) = plVar5;
      FUN_14001cf70(local_48);
      *param_2 = 1;
      lVar8 = param_1[0xc];
      goto LAB_140026bf6;
    }
LAB_140026c88:
    *param_2 = 0;
    *(undefined8 *)(param_2 + 8) = 0;
  }
  plVar5 = local_30;
  if (local_38[0] == '\x01') {
    FUN_140025800(local_30);
  }
  else if (local_38[0] == '\x02') {
    FUN_140025b90(local_30);
  }
  else {
    if (local_38[0] != '\x03') goto LAB_140026dbf;
    if (0xf < (ulonglong)local_30[3]) {
      if ((0xfff < local_30[3] + 1U) && (0x1f < (*local_30 - *(longlong *)(*local_30 + -8)) - 8U)) {
        FUN_140035d28();
        pcVar6 = (code *)swi(3);
        (*pcVar6)();
        return;
      }
      FUN_14002f180();
    }
    plVar5[2] = 0;
    plVar5[3] = 0xf;
    *(undefined1 *)plVar5 = 0;
  }
  FUN_14002f180();
LAB_140026dbf:
  FUN_14002f160(local_28 ^ (ulonglong)auStack_68);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140026df0 @ 140026df0