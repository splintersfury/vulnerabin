void FUN_14001a250(char *param_1,undefined8 param_2,undefined8 param_3,ulonglong param_4)

{
  char cVar1;
  longlong *plVar2;
  int iVar3;
  longlong *plVar4;
  char *pcVar5;
  undefined8 *puVar6;
  longlong *plVar7;
  undefined8 *****pppppuVar8;
  undefined8 *****pppppuVar9;
  ulonglong uVar10;
  longlong *plVar11;
  longlong lVar12;
  longlong *plVar13;
  undefined8 uVar14;
  ulonglong uVar15;
  size_t sVar16;
  longlong *plVar17;
  longlong lVar18;
  longlong lVar19;
  longlong *plVar20;
  bool bVar21;
  undefined1 auStack_148 [32];
  uint local_128;
  uint local_124;
  uint local_120;
  undefined8 ****local_118 [2];
  ulonglong local_108;
  ulonglong local_100;
  undefined8 ****local_f8;
  longlong local_f0;
  longlong *local_e8;
  longlong local_e0 [7];
  longlong local_a8 [4];
  longlong local_88 [7];
  undefined8 ****local_50;
  undefined8 local_48;
  undefined8 uStack_40;
  ulonglong local_38;
  ulonglong local_30;
  
  local_30 = DAT_14007a060 ^ (ulonglong)auStack_148;
  local_128 = 0;
  local_120 = 0;
  local_124 = 0;
  uStack_40 = 0;
  local_38 = 0xf;
  local_50 = (undefined8 *****)0x0;
  uVar14 = 0x10;
  FUN_1400106a0((longlong *)&local_50,(undefined8 *)"acceptedControls",0x10);
  plVar4 = FUN_14001cdf0(param_1,&local_50,uVar14,param_4);
  local_e8 = plVar4;
  if (0xf < local_38) {
    if ((0xfff < local_38 + 1) &&
       (0x1f < (ulonglong)((longlong)local_50 + (-8 - (longlong)local_50[-1])))) {
LAB_14001a747:
      FUN_140035d28();
      goto LAB_14001a74d;
    }
    FUN_14002f180();
  }
  lVar19 = -0x8000000000000000;
  lVar12 = -0x8000000000000000;
  cVar1 = (char)*plVar4;
  if (cVar1 == '\x01') {
LAB_14001a369:
    plVar11 = (longlong *)**(undefined8 **)plVar4[1];
LAB_14001a373:
    plVar13 = (longlong *)0x0;
  }
  else {
    if (cVar1 != '\x02') {
      if (cVar1 == '\0') {
        lVar12 = 1;
        plVar11 = (longlong *)0x0;
      }
      else {
        if (cVar1 == '\x01') goto LAB_14001a369;
        if (cVar1 == '\x02') goto LAB_14001a35c;
        plVar11 = (longlong *)0x0;
        lVar12 = 0;
      }
      goto LAB_14001a373;
    }
LAB_14001a35c:
    plVar13 = *(longlong **)plVar4[1];
    plVar11 = (longlong *)0x0;
  }
  local_48 = 0;
  uStack_40 = 0;
  local_38 = 0;
  cVar1 = (char)*plVar4;
  if (cVar1 == '\x01') {
LAB_14001a3b6:
    plVar17 = *(longlong **)plVar4[1];
LAB_14001a3be:
    plVar20 = (longlong *)0x0;
  }
  else {
    if (cVar1 != '\x02') {
      if (cVar1 == '\x01') goto LAB_14001a3b6;
      if (cVar1 == '\x02') goto LAB_14001a3a8;
      lVar19 = 1;
      plVar17 = (longlong *)0x0;
      goto LAB_14001a3be;
    }
LAB_14001a3a8:
    plVar20 = *(longlong **)(plVar4[1] + 8);
    plVar17 = (longlong *)0x0;
  }
LAB_14001a3c2:
  cVar1 = (char)*plVar4;
  if (cVar1 == '\x01') {
    bVar21 = plVar11 == plVar17;
  }
  else if (cVar1 == '\x02') {
    bVar21 = plVar13 == plVar20;
  }
  else {
    bVar21 = lVar12 == lVar19;
  }
  if (bVar21) {
    FUN_14002f160(local_30 ^ (ulonglong)auStack_148);
    return;
  }
  if (cVar1 == '\0') {
    FUN_14000e950((longlong *)&local_50,(undefined8 *)"cannot get value");
    FUN_140018ed0(local_e0,0xd6,&local_50);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_e0,(ThrowInfo *)&DAT_140077d70);
  }
  if (cVar1 == '\x01') {
    plVar7 = plVar11 + 8;
  }
  else {
    plVar7 = plVar13;
    if ((cVar1 != '\x02') && (plVar7 = plVar4, lVar12 != 0)) {
      FUN_14000e950((longlong *)&local_50,(undefined8 *)"cannot get value");
      FUN_140018ed0(local_e0,0xd6,&local_50);
                    /* WARNING: Subroutine does not return */
      _CxxThrowException(local_e0,(ThrowInfo *)&DAT_140077d70);
    }
  }
  uVar10 = 0;
  uStack_40 = 0;
  local_38 = 0xf;
  local_50 = (undefined8 *****)0x0;
  local_128 = local_128 | 1;
  local_120 = local_128;
  if ((char)*plVar7 != '\x03') {
    pcVar5 = FUN_14001ddd0((undefined1 *)plVar7);
    plVar4 = FUN_14000e950(local_e0,(undefined8 *)pcVar5);
    puVar6 = FUN_140011fa0(local_a8,(undefined8 *)"type must be string, but is ",plVar4,param_4);
    FUN_1400190c0(local_88,0x12e,puVar6);
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_88,(ThrowInfo *)&DAT_140077cc0);
  }
  pppppuVar9 = (undefined8 *****)plVar7[1];
  if (&local_50 != pppppuVar9) {
    pppppuVar8 = pppppuVar9 + 2;
    if ((undefined8 ****)0xf < pppppuVar9[3]) {
      pppppuVar9 = (undefined8 *****)*pppppuVar9;
    }
    FUN_1400106a0((longlong *)&local_50,pppppuVar9,(ulonglong)*pppppuVar8);
  }
  pppppuVar9 = &local_50;
  if (0xf < local_38) {
    pppppuVar9 = (undefined8 *****)local_50;
  }
  local_118[0] = (undefined8 *****)0x0;
  local_108 = 0;
  local_100 = 0xf;
  uVar15 = 0xffffffffffffffff;
  do {
    uVar15 = uVar15 + 1;
  } while (*(char *)((longlong)pppppuVar9 + uVar15) != '\0');
  FUN_1400106a0((longlong *)local_118,pppppuVar9,uVar15);
  local_f8 = local_118[0];
  pppppuVar9 = local_118;
  if (0xf < local_100) {
    pppppuVar9 = (undefined8 *****)local_118[0];
  }
  uVar15 = 0xcbf29ce484222325;
  if (local_108 != 0) {
    do {
      uVar15 = (uVar15 ^ *(byte *)(uVar10 + (longlong)pppppuVar9)) * 0x100000001b3;
      uVar10 = uVar10 + 1;
    } while (uVar10 < local_108);
  }
  lVar18 = *(longlong *)(DAT_14007d598 + 8 + (uVar15 & _DAT_14007d5b0) * 0x10);
  param_4 = local_108;
  if (lVar18 != DAT_14007d588) {
    local_f0 = *(longlong *)(DAT_14007d598 + (uVar15 & _DAT_14007d5b0) * 0x10);
    pppppuVar9 = (undefined8 *****)local_118[0];
    uVar10 = local_100;
    while( true ) {
      puVar6 = (undefined8 *)(lVar18 + 0x10);
      if (0xf < *(ulonglong *)(lVar18 + 0x28)) {
        puVar6 = (undefined8 *)*puVar6;
      }
      pppppuVar8 = local_118;
      if (0xf < uVar10) {
        pppppuVar8 = pppppuVar9;
      }
      sVar16 = param_4;
      if ((param_4 == *(size_t *)(lVar18 + 0x20)) &&
         (iVar3 = memcmp(pppppuVar8,puVar6,param_4), sVar16 = local_108,
         pppppuVar9 = (undefined8 *****)local_f8, uVar10 = local_100, iVar3 == 0)) break;
      param_4 = sVar16;
      if (lVar18 == local_f0) goto LAB_14001a582;
      lVar18 = *(longlong *)(lVar18 + 8);
    }
    if (lVar18 != 0) goto LAB_14001a589;
  }
LAB_14001a582:
  lVar18 = DAT_14007d588;
LAB_14001a589:
  if (0xf < local_100) {
    if ((0xfff < local_100 + 1) &&
       (0x1f < (ulonglong)((longlong)local_f8 + (-8 - (longlong)local_f8[-1])))) {
      FUN_140035d28();
      goto LAB_14001a747;
    }
    FUN_14002f180();
  }
  if (lVar18 != DAT_14007d588) {
    local_124 = local_124 | *(uint *)(lVar18 + 0x30);
    local_128 = local_128 & 0xfffffffe;
    if (0xf < local_38) {
      if ((0xfff < local_38 + 1) &&
         (0x1f < (ulonglong)((longlong)local_50 + (-8 - (longlong)local_50[-1]))))
      goto LAB_14001a747;
      FUN_14002f180();
    }
    plVar4 = local_e8;
    if ((char)*local_e8 == '\x01') {
      plVar7 = (longlong *)plVar11[2];
      if (*(char *)((longlong)plVar7 + 0x19) == '\0') {
        cVar1 = *(char *)(*plVar7 + 0x19);
        plVar11 = plVar7;
        plVar7 = (longlong *)*plVar7;
        while (cVar1 == '\0') {
          cVar1 = *(char *)(*plVar7 + 0x19);
          plVar11 = plVar7;
          plVar7 = (longlong *)*plVar7;
        }
      }
      else {
        cVar1 = *(char *)(plVar11[1] + 0x19);
        plVar2 = (longlong *)plVar11[1];
        plVar7 = plVar11;
        while ((plVar11 = plVar2, cVar1 == '\0' && (plVar7 == (longlong *)plVar11[2]))) {
          cVar1 = *(char *)(plVar11[1] + 0x19);
          plVar2 = (longlong *)plVar11[1];
          plVar7 = plVar11;
        }
      }
    }
    else if ((char)*local_e8 == '\x02') {
      plVar13 = plVar13 + 2;
    }
    else {
      lVar12 = lVar12 + 1;
    }
    goto LAB_14001a3c2;
  }
LAB_14001a74d:
  plVar4 = FUN_14000e950(local_88,(undefined8 *)"The accepted control \'");
  plVar4 = FUN_140021a50(local_a8,plVar4,&local_50);
  plVar4 = FUN_1400219f0(local_e0,plVar4,(undefined8 *)"\' is not recognized.");
  FUN_140001a40(local_118,plVar4);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_118,(ThrowInfo *)&DAT_140077818);
}


// FUNCTION_END

// FUNCTION_START: FUN_14001a7f0 @ 14001a7f0

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */