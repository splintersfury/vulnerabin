undefined8 FUN_140024ff0(longlong param_1)

{
  longlong *plVar1;
  char *pcVar2;
  code *pcVar3;
  char cVar4;
  char *pcVar5;
  undefined8 uVar6;
  longlong lVar7;
  undefined1 local_28 [8];
  int local_20 [6];
  
  if (*(longlong *)(*(longlong *)(param_1 + 0x10) + -8) != 0) {
    local_20[0] = (int)(*(longlong *)(param_1 + 0x10) - *(longlong *)(param_1 + 8) >> 3) + -1;
    local_28[0] = 3;
    if (*(longlong *)(param_1 + 0xa8) == 0) {
      FUN_14002d6d4();
      pcVar3 = (code *)swi(3);
      uVar6 = (*pcVar3)();
      return uVar6;
    }
    cVar4 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                      (*(longlong *)(param_1 + 0xa8),local_20,local_28);
    if (cVar4 == '\0') {
      pcVar5 = (char *)FUN_140025c20((undefined1 *)local_20,(undefined1 *)(param_1 + 0xb8));
      pcVar2 = *(char **)(*(longlong *)(param_1 + 0x10) + -8);
      cVar4 = *pcVar2;
      *pcVar2 = *pcVar5;
      *pcVar5 = cVar4;
      uVar6 = *(undefined8 *)(pcVar2 + 8);
      *(undefined8 *)(pcVar2 + 8) = *(undefined8 *)(pcVar5 + 8);
      *(undefined8 *)(pcVar5 + 8) = uVar6;
      FUN_14001cf70(pcVar5);
      *(longlong *)(param_1 + 0x10) = *(longlong *)(param_1 + 0x10) + -8;
      FUN_140025870((longlong *)(param_1 + 0x20));
      lVar7 = *(longlong *)(param_1 + 0x10);
      if ((*(longlong *)(param_1 + 8) != lVar7) && (**(char **)(lVar7 + -8) == '\x02')) {
        lVar7 = *(longlong *)(*(char **)(lVar7 + -8) + 8);
        uVar6 = FUN_14001cf70((char *)(*(longlong *)(lVar7 + 8) + -0x10));
        plVar1 = (longlong *)(lVar7 + 8);
        *plVar1 = *plVar1 + -0x10;
        return CONCAT71((int7)((ulonglong)uVar6 >> 8),1);
      }
      goto LAB_1400250d2;
    }
  }
  *(longlong *)(param_1 + 0x10) = *(longlong *)(param_1 + 0x10) + -8;
  lVar7 = FUN_140025870((longlong *)(param_1 + 0x20));
LAB_1400250d2:
  return CONCAT71((int7)((ulonglong)lVar7 >> 8),1);
}


// FUNCTION_END

// FUNCTION_START: FUN_1400250e0 @ 1400250e0