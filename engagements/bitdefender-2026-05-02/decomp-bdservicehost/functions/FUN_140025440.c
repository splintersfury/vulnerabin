void FUN_140025440(longlong param_1,undefined8 *param_2)

{
  char cVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined8 uVar4;
  code *pcVar5;
  longlong *plVar6;
  char *pcVar7;
  char *pcVar8;
  undefined1 auStackY_a8 [32];
  longlong local_78 [2];
  undefined8 local_68 [2];
  char local_58 [8];
  undefined1 local_50 [8];
  longlong *local_48;
  longlong *plStack_40;
  char local_38 [8];
  longlong *local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStackY_a8;
  local_30 = (longlong *)0x0;
  local_38[0] = '\x03';
  local_48 = (longlong *)0x0;
  plStack_40 = (longlong *)0x0;
  plVar6 = (longlong *)operator_new(0x20);
  local_48 = (longlong *)local_50;
  plStack_40 = plVar6;
  FUN_14000e990(plVar6,param_2);
  local_58[0] = '\x04';
  local_48 = (longlong *)
             CONCAT44(local_48._4_4_,
                      (int)(*(longlong *)(param_1 + 0x10) - *(longlong *)(param_1 + 8) >> 3));
  local_30 = plVar6;
  if (*(longlong *)(param_1 + 0xa8) == 0) {
LAB_140025679:
    FUN_14002d6d4();
    pcVar5 = (code *)swi(3);
    (*pcVar5)();
    return;
  }
  pcVar7 = local_38;
  local_58[0] = (*(code *)PTR__guard_dispatch_icall_14005b538)
                          (*(longlong *)(param_1 + 0xa8),&local_48,local_58);
  uVar2 = *(ulonglong *)(param_1 + 0x58);
  if (((longlong)uVar2 < 0) && (uVar2 != 0)) {
    lVar3 = -((~uVar2 >> 5) * 4 + 4);
  }
  else {
    lVar3 = (uVar2 >> 5) * 4;
  }
  local_48 = (longlong *)(*(longlong *)(param_1 + 0x40) + lVar3);
  plStack_40 = (longlong *)(ulonglong)((uint)uVar2 & 0x1f);
  FUN_1400214b0((longlong *)(param_1 + 0x40),local_78,&local_48,pcVar7,local_58);
  if ((local_58[0] != '\0') && (*(longlong *)(*(longlong *)(param_1 + 0x10) + -8) != 0)) {
    local_48 = local_78;
    pcVar7 = (char *)FUN_140025c20((undefined1 *)local_78,(undefined1 *)(param_1 + 0xb8));
    plVar6 = FUN_140028680(*(longlong **)(*(longlong *)(*(longlong *)(param_1 + 0x10) + -8) + 8),
                           local_68,param_2);
    lVar3 = *plVar6;
    pcVar8 = (char *)(lVar3 + 0x40);
    cVar1 = *pcVar8;
    *pcVar8 = *pcVar7;
    *pcVar7 = cVar1;
    uVar4 = *(undefined8 *)(lVar3 + 0x48);
    *(undefined8 *)(lVar3 + 0x48) = *(undefined8 *)(pcVar7 + 8);
    *(undefined8 *)(pcVar7 + 8) = uVar4;
    FUN_14001cf70(pcVar7);
    *(char **)(param_1 + 0x60) = pcVar8;
  }
  plVar6 = local_30;
  if (local_38[0] == '\x01') {
    FUN_140025800(local_30);
  }
  else if (local_38[0] == '\x02') {
    FUN_140025b90(local_30);
  }
  else {
    if (local_38[0] != '\x03') goto LAB_14002564d;
    if (0xf < (ulonglong)local_30[3]) {
      if ((0xfff < local_30[3] + 1U) && (0x1f < (*local_30 - *(longlong *)(*local_30 + -8)) - 8U)) {
        FUN_140035d28();
        goto LAB_140025679;
      }
      FUN_14002f180();
    }
    plVar6[2] = 0;
    plVar6[3] = 0xf;
    *(undefined1 *)plVar6 = 0;
  }
  FUN_14002f180();
LAB_14002564d:
  FUN_14002f160(local_28 ^ (ulonglong)auStackY_a8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140025680 @ 140025680