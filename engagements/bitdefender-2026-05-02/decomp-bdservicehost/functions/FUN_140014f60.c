undefined8 FUN_140014f60(longlong *param_1,ulonglong param_2)

{
  undefined1 (*pauVar1) [16];
  ulonglong uVar2;
  longlong lVar3;
  undefined8 *puVar4;
  undefined1 (*pauVar5) [16];
  undefined8 *puVar6;
  undefined8 *puVar7;
  ulonglong uVar8;
  undefined8 *puVar9;
  
  lVar3 = *param_1;
  puVar9 = (undefined8 *)0x0;
  if ((lVar3 == 0) || (puVar4 = *(undefined8 **)(lVar3 + -0xc), puVar4 == (undefined8 *)0x0)) {
    puVar4 = (undefined8 *)
             (*(code *)PTR__guard_dispatch_icall_14005b538)(&PTR_vftable_14007aca0,0x28);
    *(undefined1 *)((longlong)puVar4 + 0x21) = 1;
    *puVar4 = &PTR_vftable_14007aca0;
    puVar4[2] = 0;
    puVar4[1] = 0;
    puVar4[3] = 0x40;
    puVar7 = puVar9;
LAB_140014fe4:
    puVar6 = puVar7;
    puVar7 = puVar9;
  }
  else {
    puVar7 = (undefined8 *)(lVar3 + -0x10);
    puVar6 = puVar9;
    if (*(char *)(puVar4 + 4) == '\0') goto LAB_140014fe4;
  }
  uVar2 = param_2 * 2 + 0x16;
  pauVar5 = (undefined1 (*) [16])
            (*(code *)PTR__guard_dispatch_icall_14005b538)(*puVar4,puVar7,uVar2);
  if (pauVar5 == (undefined1 (*) [16])0x0) {
    pauVar5 = (undefined1 (*) [16])(*(code *)PTR__guard_dispatch_icall_14005b538)();
    if (pauVar5 == (undefined1 (*) [16])0x0) {
      return 0;
    }
    if (puVar7 != (undefined8 *)0x0) {
      uVar8 = puVar4[2];
      if (uVar2 < puVar4[2] * 2 + 0x16U) {
        uVar8 = param_2;
      }
      FUN_1400316b0((undefined8 *)pauVar5,puVar7,uVar8 * 2 + 0x16);
      (*(code *)PTR__guard_dispatch_icall_14005b538)(*puVar4,puVar7);
      goto LAB_14001507d;
    }
  }
  else if (puVar7 != (undefined8 *)0x0) goto LAB_14001507d;
  FUN_140031e00(pauVar5,0,uVar2);
LAB_14001507d:
  if (puVar6 != (undefined8 *)0x0) {
    uVar8 = puVar4[2];
    if (uVar2 < puVar4[2] * 2 + 0x16U) {
      uVar8 = param_2;
    }
    FUN_1400316b0((undefined8 *)pauVar5,puVar6,uVar8 * 2 + 0x16);
  }
  *(undefined4 *)*pauVar5 = 0xabcd;
  pauVar1 = pauVar5 + 1;
  *(undefined8 **)(*pauVar5 + 4) = puVar4;
  *(undefined4 *)(*pauVar5 + 0xc) = 0xabcd;
  *(undefined4 *)(pauVar5[1] + param_2 * 2 + 2) = 0xabcd;
  *param_1 = (longlong)pauVar1;
  *(undefined2 *)(*pauVar1 + param_2 * 2) = 0;
  puVar4[2] = param_2;
  *(undefined1 *)(puVar4 + 4) = 1;
  if (param_2 < (ulonglong)puVar4[1]) {
    puVar4[1] = param_2;
  }
  return CONCAT71((int7)((ulonglong)pauVar1 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_140015110 @ 140015110