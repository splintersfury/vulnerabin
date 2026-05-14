void FUN_140017450(longlong param_1,ulonglong param_2)

{
  longlong *plVar1;
  longlong *plVar2;
  longlong *plVar3;
  longlong *plVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  code *pcVar7;
  longlong *plVar8;
  ulonglong uVar9;
  longlong lVar10;
  undefined8 *puVar11;
  
  for (lVar10 = 0x3f; 0xfffffffffffffffU >> lVar10 == 0; lVar10 = lVar10 + -1) {
  }
  if ((ulonglong)(1L << ((byte)lVar10 & 0x3f)) < param_2) {
    FUN_14002d6f4(0x14006bd78);
    pcVar7 = (code *)swi(3);
    (*pcVar7)();
    return;
  }
  plVar1 = *(longlong **)(param_1 + 8);
  uVar9 = param_2 - 1 | 1;
  lVar10 = 0x3f;
  if (uVar9 != 0) {
    for (; uVar9 >> lVar10 == 0; lVar10 = lVar10 + -1) {
    }
  }
  lVar10 = 1L << ((char)lVar10 + 1U & 0x3f);
  FUN_140016fb0((ulonglong *)(param_1 + 0x18),lVar10 * 2,plVar1);
  *(longlong *)(param_1 + 0x38) = lVar10;
  *(longlong *)(param_1 + 0x30) = lVar10 + -1;
  plVar8 = (longlong *)**(undefined8 **)(param_1 + 8);
joined_r0x0001400174c2:
  do {
    while( true ) {
      while( true ) {
        if (plVar8 == plVar1) {
          return;
        }
        plVar2 = (longlong *)*plVar8;
        puVar11 = (undefined8 *)
                  ((*(ulonglong *)(param_1 + 0x30) &
                   (((((ulonglong)*(byte *)(plVar8 + 2) ^ 0xcbf29ce484222325) * 0x100000001b3 ^
                     (ulonglong)*(byte *)((longlong)plVar8 + 0x11)) * 0x100000001b3 ^
                    (ulonglong)*(byte *)((longlong)plVar8 + 0x12)) * 0x100000001b3 ^
                   (ulonglong)*(byte *)((longlong)plVar8 + 0x13)) * 0x100000001b3) * 0x10 +
                  *(longlong *)(param_1 + 0x18));
        if ((longlong *)*puVar11 != plVar1) break;
        *puVar11 = plVar8;
        puVar11[1] = plVar8;
        plVar8 = plVar2;
      }
      plVar3 = (longlong *)puVar11[1];
      if ((int)plVar8[2] != (int)plVar3[2]) break;
      plVar3 = (longlong *)*plVar3;
      if (plVar3 != plVar8) {
        plVar4 = (longlong *)plVar8[1];
        *plVar4 = (longlong)plVar2;
        puVar5 = (undefined8 *)plVar2[1];
        *puVar5 = plVar3;
        puVar6 = (undefined8 *)plVar3[1];
        *puVar6 = plVar8;
        plVar3[1] = (longlong)puVar5;
        plVar2[1] = (longlong)plVar4;
        plVar8[1] = (longlong)puVar6;
      }
      puVar11[1] = plVar8;
      plVar8 = plVar2;
    }
    do {
      if ((longlong *)*puVar11 == plVar3) {
        plVar4 = (longlong *)plVar8[1];
        *plVar4 = (longlong)plVar2;
        puVar5 = (undefined8 *)plVar2[1];
        *puVar5 = plVar3;
        puVar6 = (undefined8 *)plVar3[1];
        *puVar6 = plVar8;
        plVar3[1] = (longlong)puVar5;
        plVar2[1] = (longlong)plVar4;
        plVar8[1] = (longlong)puVar6;
        *puVar11 = plVar8;
        plVar8 = plVar2;
        goto joined_r0x0001400174c2;
      }
      plVar3 = (longlong *)plVar3[1];
    } while ((int)plVar8[2] != (int)plVar3[2]);
    lVar10 = *plVar3;
    plVar3 = (longlong *)plVar8[1];
    *plVar3 = (longlong)plVar2;
    plVar4 = (longlong *)plVar2[1];
    *plVar4 = lVar10;
    puVar11 = *(undefined8 **)(lVar10 + 8);
    *puVar11 = plVar8;
    *(longlong **)(lVar10 + 8) = plVar4;
    plVar2[1] = (longlong)plVar3;
    plVar8[1] = (longlong)puVar11;
    plVar8 = plVar2;
  } while( true );
}


// FUNCTION_END

// FUNCTION_START: FUN_140017620 @ 140017620