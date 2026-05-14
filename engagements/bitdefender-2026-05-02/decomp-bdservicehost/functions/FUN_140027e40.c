void FUN_140027e40(undefined8 *param_1,undefined1 *param_2,undefined1 *param_3)

{
  longlong lVar1;
  uint uVar2;
  ulonglong uVar3;
  char *pcVar4;
  undefined8 uVar5;
  longlong *plVar6;
  longlong lVar7;
  code *pcVar8;
  char cVar9;
  char cVar10;
  ulonglong uVar11;
  undefined1 auStack_78 [48];
  char local_48 [8];
  longlong *local_40;
  undefined1 local_38 [8];
  undefined4 local_30;
  undefined4 uStack_2c;
  undefined8 local_28;
  ulonglong local_20;
  
  local_20 = DAT_14007a060 ^ (ulonglong)auStack_78;
  uVar3 = param_1[7];
  if (((longlong)uVar3 < 0) && (uVar3 != 0)) {
    lVar7 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    lVar7 = (uVar3 >> 5) * 4;
  }
  uVar11 = (ulonglong)((uint)uVar3 & 0x1f);
  uVar3 = uVar11 - 1;
  if (uVar11 == 0) {
    lVar1 = -((~uVar3 >> 5) * 4 + 4);
  }
  else {
    lVar1 = (uVar3 >> 5) * 4;
  }
  if ((*(uint *)(param_1[4] + lVar7 + lVar1) >> ((byte)uVar3 & 0x1f) & 1) == 0) {
    *param_2 = 0;
    *(undefined8 *)(param_2 + 8) = 0;
    goto LAB_14002815e;
  }
  local_48[0] = '\x04';
  local_30 = CONCAT31(local_30._1_3_,*param_3);
  local_40 = (longlong *)CONCAT44(uStack_2c,local_30);
  local_38[0] = 5;
  local_30 = (undefined4)((longlong)(param_1[2] - param_1[1]) >> 3);
  if (param_1[0x15] == 0) goto LAB_140028188;
  cVar10 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1[0x15],&local_30,local_38,local_48)
  ;
  plVar6 = local_40;
  cVar9 = local_48[0];
  if (cVar10 == '\0') {
LAB_140027f45:
    *param_2 = 0;
    *(undefined8 *)(param_2 + 8) = 0;
  }
  else if (param_1[1] == param_1[2]) {
    local_48[0] = '\0';
    local_40 = (longlong *)0x0;
    pcVar4 = (char *)*param_1;
    cVar10 = *pcVar4;
    *pcVar4 = cVar9;
    local_30 = CONCAT31(local_30._1_3_,cVar10);
    local_28 = *(undefined8 *)(pcVar4 + 8);
    *(longlong **)(pcVar4 + 8) = plVar6;
    FUN_14001cf70((char *)&local_30);
    uVar5 = *param_1;
    *param_2 = 1;
    *(undefined8 *)(param_2 + 8) = uVar5;
  }
  else {
    pcVar4 = *(char **)(param_1[2] + -8);
    if (pcVar4 == (char *)0x0) goto LAB_140027f45;
    if (*pcVar4 == '\x02') {
      plVar6 = *(longlong **)(pcVar4 + 8);
      pcVar4 = (char *)plVar6[1];
      if (pcVar4 == (char *)plVar6[2]) {
        FUN_140029c40(plVar6,pcVar4,local_48);
      }
      else {
        *pcVar4 = local_48[0];
        *(longlong **)(pcVar4 + 8) = local_40;
        local_48[0] = '\0';
        local_40 = (longlong *)0x0;
        plVar6[1] = plVar6[1] + 0x10;
      }
      lVar7 = *(longlong *)(*(longlong *)(*(longlong *)(param_1[2] + -8) + 8) + 8);
      *param_2 = 1;
      *(longlong *)(param_2 + 8) = lVar7 + -0x10;
    }
    else {
      uVar3 = param_1[0xb];
      if (((longlong)uVar3 < 0) && (uVar3 != 0)) {
        lVar7 = -((~uVar3 >> 5) * 4 + 4);
      }
      else {
        lVar7 = (uVar3 >> 5) * 4;
      }
      uVar11 = (ulonglong)((uint)uVar3 & 0x1f);
      uVar3 = uVar11 - 1;
      if (uVar11 == 0) {
        lVar1 = -((~uVar3 >> 5) * 4 + 4);
      }
      else {
        lVar1 = (uVar3 >> 5) * 4;
      }
      uVar2 = *(uint *)(param_1[8] + lVar7 + lVar1);
      FUN_140025870(param_1 + 8);
      plVar6 = local_40;
      cVar9 = local_48[0];
      if ((uVar2 >> ((byte)uVar3 & 0x1f) & 1) == 0) goto LAB_140027f45;
      local_48[0] = '\0';
      local_40 = (longlong *)0x0;
      pcVar4 = (char *)param_1[0xc];
      cVar10 = *pcVar4;
      *pcVar4 = cVar9;
      local_30 = CONCAT31(local_30._1_3_,cVar10);
      local_28 = *(undefined8 *)(pcVar4 + 8);
      *(longlong **)(pcVar4 + 8) = plVar6;
      FUN_14001cf70((char *)&local_30);
      *param_2 = 1;
      *(undefined8 *)(param_2 + 8) = param_1[0xc];
    }
  }
  plVar6 = local_40;
  if (local_48[0] == '\x01') {
    FUN_140025800(local_40);
  }
  else if (local_48[0] == '\x02') {
    FUN_140025b90(local_40);
  }
  else {
    if (local_48[0] != '\x03') goto LAB_14002815e;
    if (0xf < (ulonglong)local_40[3]) {
      if ((0xfff < local_40[3] + 1U) && (0x1f < (*local_40 - *(longlong *)(*local_40 + -8)) - 8U)) {
        FUN_140035d28();
LAB_140028188:
        FUN_14002d6d4();
        pcVar8 = (code *)swi(3);
        (*pcVar8)();
        return;
      }
      FUN_14002f180();
    }
    plVar6[2] = 0;
    plVar6[3] = 0xf;
    *(undefined1 *)plVar6 = 0;
  }
  FUN_14002f180();
LAB_14002815e:
  FUN_14002f160(local_20 ^ (ulonglong)auStack_78);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140028190 @ 140028190