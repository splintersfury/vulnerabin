void FUN_140025c20(undefined1 *param_1,undefined1 *param_2)

{
  char cVar1;
  longlong lVar2;
  longlong lVar3;
  undefined1 *puVar4;
  undefined8 *puVar5;
  code *pcVar6;
  longlong *plVar7;
  longlong *plVar8;
  longlong *plVar9;
  void *pvVar10;
  longlong *plVar11;
  ulonglong uVar12;
  undefined1 *puVar13;
  undefined1 *puVar14;
  undefined1 auStack_98 [32];
  undefined1 local_78 [8];
  longlong *local_70;
  longlong *plStack_68;
  longlong *local_60;
  longlong *plStack_58;
  undefined1 *local_50;
  undefined1 *puStack_48;
  longlong *local_40;
  ulonglong local_38;
  
  local_38 = DAT_14007a060 ^ (ulonglong)auStack_98;
  *param_1 = *param_2;
  *(undefined8 *)(param_1 + 8) = 0;
  switch(*param_1) {
  case 1:
    plVar11 = *(longlong **)(param_2 + 8);
    local_60 = (longlong *)0x0;
    plStack_58 = (longlong *)0x0;
    plVar8 = (longlong *)operator_new(0x10);
    local_60 = (longlong *)local_78;
    *plVar8 = 0;
    plVar8[1] = 0;
    local_70 = plVar8;
    plStack_68 = plVar8;
    plStack_58 = plVar8;
    pvVar10 = operator_new(0x50);
    *(void **)pvVar10 = pvVar10;
    *(void **)((longlong)pvVar10 + 8) = pvVar10;
    *(void **)((longlong)pvVar10 + 0x10) = pvVar10;
    *(undefined2 *)((longlong)pvVar10 + 0x18) = 0x101;
    *plVar8 = (longlong)pvVar10;
    plVar9 = FUN_14002a4c0(plVar8,*(undefined8 **)(*plVar11 + 8),(longlong)pvVar10,local_78[0]);
    *(longlong **)(*plVar8 + 8) = plVar9;
    plVar8[1] = plVar11[1];
    plVar11 = (longlong *)*plVar8;
    plVar9 = (longlong *)plVar11[1];
    if (*(char *)((longlong)plVar9 + 0x19) == '\0') {
      cVar1 = *(char *)(*plVar9 + 0x19);
      plVar7 = (longlong *)*plVar9;
      while (cVar1 == '\0') {
        cVar1 = *(char *)(*plVar7 + 0x19);
        plVar9 = plVar7;
        plVar7 = (longlong *)*plVar7;
      }
      *plVar11 = (longlong)plVar9;
      lVar2 = *(longlong *)(*plVar8 + 8);
      lVar3 = *(longlong *)(lVar2 + 0x10);
      cVar1 = *(char *)(lVar3 + 0x19);
      while (cVar1 == '\0') {
        cVar1 = *(char *)(*(longlong *)(lVar3 + 0x10) + 0x19);
        lVar2 = lVar3;
        lVar3 = *(longlong *)(lVar3 + 0x10);
      }
      *(longlong *)(*plVar8 + 0x10) = lVar2;
    }
    else {
      *plVar11 = (longlong)plVar11;
      *(longlong *)(*plVar8 + 0x10) = *plVar8;
    }
    *(longlong **)(param_1 + 8) = plVar8;
    break;
  case 2:
    plVar11 = *(longlong **)(param_2 + 8);
    local_70 = (longlong *)0x0;
    plStack_68 = (longlong *)0x0;
    plVar9 = (longlong *)operator_new(0x18);
    local_70 = (longlong *)local_78;
    puVar14 = (undefined1 *)0x0;
    *plVar9 = 0;
    plVar9[1] = 0;
    plVar9[2] = 0;
    puVar13 = (undefined1 *)*plVar11;
    puVar4 = (undefined1 *)plVar11[1];
    plStack_68 = plVar9;
    if (puVar13 != puVar4) {
      uVar12 = (longlong)puVar4 - (longlong)puVar13 >> 4;
      if (0xfffffffffffffff < uVar12) {
LAB_140025eda:
        FUN_140001670();
LAB_140025ee0:
        FUN_140035d28();
        pcVar6 = (code *)swi(3);
        (*pcVar6)();
        return;
      }
      uVar12 = uVar12 * 0x10;
      if (uVar12 < 0x1000) {
        if (uVar12 != 0) {
          puVar14 = (undefined1 *)operator_new(uVar12);
        }
      }
      else {
        if (uVar12 + 0x27 <= uVar12) goto LAB_140025eda;
        pvVar10 = operator_new(uVar12 + 0x27);
        if (pvVar10 == (void *)0x0) goto LAB_140025ee0;
        puVar14 = (undefined1 *)((longlong)pvVar10 + 0x27U & 0xffffffffffffffe0);
        *(void **)(puVar14 + -8) = pvVar10;
      }
      *plVar9 = (longlong)puVar14;
      plVar9[1] = (longlong)puVar14;
      plVar9[2] = (longlong)(puVar14 + uVar12);
      local_60 = plVar9;
      local_50 = puVar14;
      local_40 = plVar9;
      do {
        puStack_48 = puVar14;
        FUN_140025c20(puVar14,puVar13);
        puVar14 = puVar14 + 0x10;
        puVar13 = puVar13 + 0x10;
      } while (puVar13 != puVar4);
      plVar9[1] = (longlong)puVar14;
      puStack_48 = puVar14;
    }
    *(longlong **)(param_1 + 8) = plVar9;
    break;
  case 3:
    puVar5 = *(undefined8 **)(param_2 + 8);
    local_70 = (longlong *)0x0;
    plStack_68 = (longlong *)0x0;
    plVar11 = (longlong *)operator_new(0x20);
    local_70 = (longlong *)local_78;
    plStack_68 = plVar11;
    FUN_14000e990(plVar11,puVar5);
    *(longlong **)(param_1 + 8) = plVar11;
    break;
  case 4:
    local_60 = (longlong *)CONCAT71(local_60._1_7_,param_2[8]);
    *(longlong **)(param_1 + 8) = local_60;
    break;
  case 5:
  case 6:
    *(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_2 + 8);
    break;
  case 7:
    *(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_2 + 8);
  }
  FUN_14002f160(local_38 ^ (ulonglong)auStack_98);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140025f10 @ 140025f10