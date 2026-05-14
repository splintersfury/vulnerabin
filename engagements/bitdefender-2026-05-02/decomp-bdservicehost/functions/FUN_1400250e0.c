void FUN_1400250e0(longlong param_1)

{
  char cVar1;
  char *pcVar2;
  undefined8 uVar3;
  longlong *plVar4;
  longlong *plVar5;
  code *pcVar6;
  char cVar7;
  char *pcVar8;
  longlong *plVar9;
  longlong *plVar10;
  longlong *plVar11;
  longlong lVar12;
  longlong lVar13;
  longlong *plVar14;
  bool bVar15;
  undefined1 auStack_f8 [48];
  longlong *local_c8;
  longlong *local_c0;
  longlong *plStack_b8;
  longlong local_b0;
  undefined8 local_a0;
  undefined8 uStack_98;
  undefined8 uStack_90;
  undefined8 local_88 [7];
  undefined1 local_50 [8];
  int local_48 [2];
  longlong *local_40;
  longlong *plStack_38;
  longlong local_30;
  ulonglong local_28;
  
  local_28 = DAT_14007a060 ^ (ulonglong)auStack_f8;
  if (*(longlong *)(*(longlong *)(param_1 + 0x10) + -8) != 0) {
    local_48[0] = (int)(*(longlong *)(param_1 + 0x10) - *(longlong *)(param_1 + 8) >> 3) + -1;
    local_50[0] = 1;
    if (*(longlong *)(param_1 + 0xa8) == 0) {
      FUN_14002d6d4();
      pcVar6 = (code *)swi(3);
      (*pcVar6)();
      return;
    }
    cVar7 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                      (*(longlong *)(param_1 + 0xa8),local_48,local_50);
    if (cVar7 == '\0') {
      pcVar8 = (char *)FUN_140025c20((undefined1 *)local_48,(undefined1 *)(param_1 + 0xb8));
      pcVar2 = *(char **)(*(longlong *)(param_1 + 0x10) + -8);
      cVar7 = *pcVar2;
      *pcVar2 = *pcVar8;
      *pcVar8 = cVar7;
      uVar3 = *(undefined8 *)(pcVar2 + 8);
      *(undefined8 *)(pcVar2 + 8) = *(undefined8 *)(pcVar8 + 8);
      *(undefined8 *)(pcVar8 + 8) = uVar3;
      FUN_14001cf70(pcVar8);
    }
  }
  *(longlong *)(param_1 + 0x10) = *(longlong *)(param_1 + 0x10) + -8;
  FUN_140025870((longlong *)(param_1 + 0x20));
  if (((*(longlong *)(param_1 + 8) == *(longlong *)(param_1 + 0x10)) ||
      (plVar4 = *(longlong **)(*(longlong *)(param_1 + 0x10) + -8), plVar4 == (longlong *)0x0)) ||
     ((char)*plVar4 != '\x01')) goto LAB_1400253a3;
  local_40 = (longlong *)0x0;
  plStack_38 = (longlong *)0x0;
  lVar13 = -0x8000000000000000;
  local_30 = -0x8000000000000000;
  cVar7 = (char)*plVar4;
  if (cVar7 == '\x01') {
LAB_140025234:
    local_40 = (longlong *)**(longlong **)plVar4[1];
  }
  else if (cVar7 == '\x02') {
LAB_140025223:
    plStack_38 = *(longlong **)plVar4[1];
  }
  else if (cVar7 == '\0') {
    lVar13 = 1;
    local_30 = 1;
  }
  else {
    if (cVar7 == '\x01') goto LAB_140025234;
    if (cVar7 == '\x02') goto LAB_140025223;
    lVar13 = 0;
    local_30 = 0;
  }
  plVar5 = *(longlong **)(*(longlong *)(param_1 + 0x10) + -8);
  plVar9 = local_40;
  plVar14 = plStack_38;
LAB_140025250:
  local_a0 = 0;
  uStack_98 = 0;
  uStack_90 = 0;
  lVar12 = -0x8000000000000000;
  cVar1 = (char)*plVar5;
  if (cVar1 == '\x01') {
LAB_140025299:
    plVar10 = *(longlong **)plVar5[1];
LAB_1400252a0:
    plVar11 = (longlong *)0x0;
  }
  else {
    if (cVar1 != '\x02') {
      if (cVar1 == '\x01') goto LAB_140025299;
      if (cVar1 == '\x02') goto LAB_14002528b;
      lVar12 = 1;
      plVar10 = (longlong *)0x0;
      goto LAB_1400252a0;
    }
LAB_14002528b:
    plVar11 = *(longlong **)(plVar5[1] + 8);
    plVar10 = (longlong *)0x0;
  }
  if (plVar4 != plVar5) {
    FUN_14000e950((longlong *)&local_c8,
                  (undefined8 *)"cannot compare iterators of different containers");
    FUN_140018ed0(local_88,0xd4,&local_c8);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_88,(ThrowInfo *)&DAT_140077d70);
  }
  if (cVar7 == '\x01') {
    bVar15 = plVar9 == plVar10;
  }
  else if (cVar7 == '\x02') {
    bVar15 = plVar14 == plVar11;
  }
  else {
    bVar15 = lVar13 == lVar12;
  }
  if (bVar15) goto LAB_1400253a3;
  if (cVar7 == '\x01') {
    plVar10 = plVar9 + 8;
  }
  else {
    plVar10 = plVar14;
    if ((cVar7 != '\x02') && (plVar10 = plVar4, lVar13 != 0)) {
      FUN_14000e950((longlong *)&local_c8,(undefined8 *)"cannot get value");
      FUN_140018ed0(local_88,0xd6,&local_c8);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_88,(ThrowInfo *)&DAT_140077d70);
    }
  }
  if ((char)*plVar10 != '\b') {
    if (cVar7 == '\x01') {
      plVar10 = (longlong *)plVar9[2];
      if (*(char *)((longlong)plVar10 + 0x19) == '\0') {
        cVar1 = *(char *)(*plVar10 + 0x19);
        plVar9 = plVar10;
        plVar10 = (longlong *)*plVar10;
        while (local_40 = plVar9, cVar1 == '\0') {
          cVar1 = *(char *)(*plVar10 + 0x19);
          plVar9 = plVar10;
          plVar10 = (longlong *)*plVar10;
        }
      }
      else {
        cVar1 = *(char *)(plVar9[1] + 0x19);
        plVar11 = (longlong *)plVar9[1];
        plVar10 = plVar9;
        while ((plVar9 = plVar11, local_40 = plVar9, cVar1 == '\0' &&
               (plVar10 == (longlong *)plVar9[2]))) {
          cVar1 = *(char *)(plVar9[1] + 0x19);
          plVar11 = (longlong *)plVar9[1];
          plVar10 = plVar9;
        }
      }
    }
    else if (cVar7 == '\x02') {
      plVar14 = plVar14 + 2;
      plStack_38 = plVar14;
    }
    else {
      lVar13 = lVar13 + 1;
      local_30 = lVar13;
    }
    goto LAB_140025250;
  }
  local_c0 = local_40;
  plStack_b8 = plStack_38;
  local_b0 = local_30;
  local_c8 = plVar4;
  FUN_140026df0(*(char **)(*(longlong *)(param_1 + 0x10) + -8),local_88,&local_c8,lVar13);
LAB_1400253a3:
  FUN_14002f160(local_28 ^ (ulonglong)auStack_f8);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140025440 @ 140025440