longlong * FUN_140017620(longlong param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  longlong lVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  longlong lVar6;
  longlong *in_RAX;
  undefined8 *puVar7;
  longlong *plVar8;
  longlong *plVar9;
  longlong *plVar10;
  longlong *plVar11;
  
  if (*(ulonglong *)(param_1 + 0x10) != 0) {
    if (*(ulonglong *)(param_1 + 0x10) < *(ulonglong *)(param_1 + 0x38) >> 3) {
      plVar1 = *(longlong **)(param_1 + 8);
      plVar2 = (longlong *)*plVar1;
      if (plVar2 == plVar1) {
        return plVar1;
      }
      lVar3 = *(longlong *)(param_1 + 0x18);
      puVar4 = *(undefined8 **)(param_1 + 8);
      puVar5 = (undefined8 *)plVar2[1];
      plVar11 = (longlong *)
                ((*(ulonglong *)(param_1 + 0x30) &
                 (((((ulonglong)*(byte *)(plVar2 + 2) ^ 0xcbf29ce484222325) * 0x100000001b3 ^
                   (ulonglong)*(byte *)((longlong)plVar2 + 0x11)) * 0x100000001b3 ^
                  (ulonglong)*(byte *)((longlong)plVar2 + 0x12)) * 0x100000001b3 ^
                 (ulonglong)*(byte *)((longlong)plVar2 + 0x13)) * 0x100000001b3) * 0x10 + lVar3);
      lVar6 = *plVar11;
      plVar10 = (longlong *)plVar11[1];
      plVar8 = plVar2;
      do {
        plVar9 = (longlong *)*plVar8;
        FUN_14002f180();
        *(longlong *)(param_1 + 0x10) = *(longlong *)(param_1 + 0x10) + -1;
        if (plVar8 == plVar10) {
          puVar7 = puVar5;
          if ((longlong *)lVar6 == plVar2) {
            *plVar11 = (longlong)puVar4;
            puVar7 = puVar4;
          }
          plVar11[1] = (longlong)puVar7;
          while (plVar9 != plVar1) {
            plVar11 = (longlong *)
                      ((*(ulonglong *)(param_1 + 0x30) &
                       (((((ulonglong)*(byte *)(plVar9 + 2) ^ 0xcbf29ce484222325) * 0x100000001b3 ^
                         (ulonglong)*(byte *)((longlong)plVar9 + 0x11)) * 0x100000001b3 ^
                        (ulonglong)*(byte *)((longlong)plVar9 + 0x12)) * 0x100000001b3 ^
                       (ulonglong)*(byte *)((longlong)plVar9 + 0x13)) * 0x100000001b3) * 0x10 +
                      lVar3);
            plVar2 = (longlong *)plVar11[1];
            plVar10 = plVar9;
            while( true ) {
              plVar9 = (longlong *)*plVar10;
              FUN_14002f180();
              *(longlong *)(param_1 + 0x10) = *(longlong *)(param_1 + 0x10) + -1;
              if (plVar10 == plVar2) break;
              plVar10 = plVar9;
              if (plVar9 == plVar1) goto LAB_1400177ba;
            }
            *plVar11 = (longlong)puVar4;
            plVar11[1] = (longlong)puVar4;
          }
          goto LAB_1400177bd;
        }
        plVar8 = plVar9;
      } while (plVar9 != plVar1);
      if ((longlong *)lVar6 == plVar2) {
LAB_1400177ba:
        *plVar11 = (longlong)plVar9;
      }
LAB_1400177bd:
      *puVar5 = plVar9;
      plVar9[1] = (longlong)puVar5;
      return plVar1;
    }
    puVar4 = *(undefined8 **)(param_1 + 8);
    *(undefined8 *)puVar4[1] = 0;
    puVar4 = (undefined8 *)*puVar4;
    while (puVar4 != (undefined8 *)0x0) {
      puVar4 = (undefined8 *)*puVar4;
      FUN_14002f180();
    }
    *(undefined8 *)*(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_1 + 8);
    *(longlong *)(*(longlong *)(param_1 + 8) + 8) = *(longlong *)(param_1 + 8);
    *(undefined8 *)(param_1 + 0x10) = 0;
    in_RAX = (longlong *)
             FUN_1400170f0(*(undefined8 **)(param_1 + 0x18),*(undefined8 **)(param_1 + 0x20),
                           (undefined8 *)&stack0xffffffffffffffe8);
  }
  return in_RAX;
}


// FUNCTION_END

// FUNCTION_START: FUN_1400178b0 @ 1400178b0