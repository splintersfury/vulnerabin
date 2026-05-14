void FUN_1400270e0(undefined8 *param_1,undefined1 *param_2,undefined8 *param_3)

{
  longlong lVar1;
  uint uVar2;
  ulonglong uVar3;
  char *pcVar4;
  undefined8 uVar5;
  longlong lVar6;
  code *pcVar7;
  char cVar8;
  char cVar9;
  longlong *plVar10;
  ulonglong uVar11;
  undefined1 auStack_98 [48];
  char local_68 [8];
  longlong *local_60;
  undefined1 local_58 [8];
  undefined1 local_50 [8];
  undefined1 *local_48;
  longlong *plStack_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_98;
  uVar3 = param_1[7];
  if (((longlong)uVar3 < 0) && (uVar3 != 0)) {
    lVar6 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    lVar6 = (uVar3 >> 5) * 4;
  }
  uVar11 = (ulonglong)((uint)uVar3 & 0x1f);
  uVar3 = uVar11 - 1;
  if (uVar11 == 0) {
    lVar1 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    lVar1 = (uVar3 >> 5) * 4;
  }
  if ((*(uint *)(param_1[4] + lVar6 + lVar1) >> ((byte)uVar3 & 0x1f) & 1) == 0) {
    *param_2 = 0;
    *(undefined8 *)(param_2 + 8) = 0;
    goto LAB_140027420;
  }
  local_60 = (longlong *)0x0;
  local_68[0] = '\x03';
  local_48 = (undefined1 *)0x0;
  plStack_40 = (longlong *)0x0;
  plVar10 = (longlong *)operator_new(0x20);
  local_48 = local_50;
  plStack_40 = plVar10;
  FUN_14000e990(plVar10,param_3);
  local_58[0] = 5;
  local_48 = (undefined1 *)CONCAT44(local_48._4_4_,(int)((longlong)(param_1[2] - param_1[1]) >> 3));
  local_60 = plVar10;
  if (param_1[0x15] == 0) goto LAB_140027440;
  cVar9 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1[0x15],&local_48,local_58,local_68);
  plVar10 = local_60;
  cVar8 = local_68[0];
  if (cVar9 == '\0') {
LAB_140027207:
    *param_2 = 0;
    *(undefined8 *)(param_2 + 8) = 0;
  }
  else if (param_1[1] == param_1[2]) {
    local_68[0] = '\0';
    local_60 = (longlong *)0x0;
    pcVar4 = (char *)*param_1;
    cVar9 = *pcVar4;
    *pcVar4 = cVar8;
    local_48 = (undefined1 *)CONCAT71(local_48._1_7_,cVar9);
    plStack_40 = *(longlong **)(pcVar4 + 8);
    *(longlong **)(pcVar4 + 8) = plVar10;
    FUN_14001cf70((char *)&local_48);
    uVar5 = *param_1;
    *param_2 = 1;
    *(undefined8 *)(param_2 + 8) = uVar5;
  }
  else {
    pcVar4 = *(char **)(param_1[2] + -8);
    if (pcVar4 == (char *)0x0) goto LAB_140027207;
    if (*pcVar4 == '\x02') {
      plVar10 = *(longlong **)(pcVar4 + 8);
      pcVar4 = (char *)plVar10[1];
      if (pcVar4 == (char *)plVar10[2]) {
        FUN_140029c40(plVar10,pcVar4,local_68);
      }
      else {
        *pcVar4 = local_68[0];
        *(longlong **)(pcVar4 + 8) = local_60;
        local_68[0] = '\0';
        local_60 = (longlong *)0x0;
        plVar10[1] = plVar10[1] + 0x10;
      }
      lVar6 = *(longlong *)(*(longlong *)(*(longlong *)(param_1[2] + -8) + 8) + 8);
      *param_2 = 1;
      *(longlong *)(param_2 + 8) = lVar6 + -0x10;
    }
    else {
      uVar3 = param_1[0xb];
      if (((longlong)uVar3 < 0) && (uVar3 != 0)) {
        lVar6 = -((~uVar3 >> 5) * 4 + 4);
      }
      else {
        lVar6 = (uVar3 >> 5) * 4;
      }
      uVar11 = (ulonglong)((uint)uVar3 & 0x1f);
      uVar3 = uVar11 - 1;
      if (uVar11 == 0) {
        lVar1 = -((~uVar3 >> 5) * 4 + 4);
      }
      else {
        lVar1 = (uVar3 >> 5) * 4;
      }
      uVar2 = *(uint *)(param_1[8] + lVar6 + lVar1);
      FUN_140025870(param_1 + 8);
      plVar10 = local_60;
      cVar8 = local_68[0];
      if ((uVar2 >> ((byte)uVar3 & 0x1f) & 1) == 0) goto LAB_140027207;
      local_68[0] = '\0';
      local_60 = (longlong *)0x0;
      pcVar4 = (char *)param_1[0xc];
      cVar9 = *pcVar4;
      *pcVar4 = cVar8;
      local_48 = (undefined1 *)CONCAT71(local_48._1_7_,cVar9);
      plStack_40 = *(longlong **)(pcVar4 + 8);
      *(longlong **)(pcVar4 + 8) = plVar10;
      FUN_14001cf70((char *)&local_48);
      *param_2 = 1;
      *(undefined8 *)(param_2 + 8) = param_1[0xc];
    }
  }
  plVar10 = local_60;
  if (local_68[0] == '\x01') {
    FUN_140025800(local_60);
  }
  else if (local_68[0] == '\x02') {
    FUN_140025b90(local_60);
  }
  else {
    if (local_68[0] != '\x03') goto LAB_140027420;
    if (0xf < (ulonglong)local_60[3]) {
      if ((0xfff < local_60[3] + 1U) && (0x1f < (*local_60 - *(longlong *)(*local_60 + -8)) - 8U)) {
        FUN_140035d28();
LAB_140027440:
        FUN_14002d6d4();
        pcVar7 = (code *)swi(3);
        (*pcVar7)();
        return;
      }
      FUN_14002f180();
    }
    plVar10[2] = 0;
    plVar10[3] = 0xf;
    *(undefined1 *)plVar10 = 0;
  }
  FUN_14002f180();
LAB_140027420:
  FUN_14002f160(local_38 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140027450 @ 140027450