void FUN_140008d70(DWORD *param_1)

{
  code *pcVar1;
  
  if (param_1 != (DWORD *)0x0) {
    Sleep(*param_1);
  }
  terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008d90 @ 140008d90

uint FUN_140008d90(undefined1 (*param_1) [16])

{
  ushort uVar1;
  uint uVar2;
  undefined1 (*pauVar3) [16];
  ushort *puVar4;
  ushort *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  
  if (param_1 == (undefined1 (*) [16])0x0) {
    return 0xffffffff;
  }
  pauVar3 = FUN_140031398(param_1,(undefined1 (*) [16])&DAT_14006ad80);
  iVar7 = 0;
  uVar6 = 0;
  if ((pauVar3 != (undefined1 (*) [16])0x0) &&
     (((pauVar3 <= param_1 || (*(short *)(pauVar3[-1] + 0xe) == 0x20)) ||
      (*(short *)(pauVar3[-1] + 0xe) == 9)))) {
    puVar5 = (ushort *)(*pauVar3 + 0xe);
    puVar4 = FUN_14003131c(puVar5,0x23);
    if (((puVar4 != (ushort *)0x0) && (puVar4[1] < 0x21)) &&
       ((0x100000201U >> ((ulonglong)puVar4[1] & 0x3f) & 1) != 0)) {
      uVar2 = 0;
      iVar8 = 0;
      if (puVar5 < puVar4) {
        do {
          uVar1 = *puVar5;
          if ((9 < (ushort)(uVar1 - 0x30)) || (86400000 < uVar2)) goto LAB_140008e6c;
          iVar8 = iVar8 + 1;
          puVar5 = puVar5 + 1;
          uVar2 = (uint)uVar1 + (uVar2 * 5 + -0x18) * 2;
        } while (puVar5 < puVar4);
        if ((iVar8 != 0) && (DAT_14007d600 = &DAT_14006ad80, -1 < (int)uVar2)) {
          DAT_14007d600 = &DAT_14006ad80;
          return uVar2;
        }
      }
    }
  }
LAB_140008e6c:
  pauVar3 = FUN_140031398(param_1,(undefined1 (*) [16])&DAT_14006ad90);
  if ((pauVar3 != (undefined1 (*) [16])0x0) &&
     (((pauVar3 <= param_1 || (*(short *)(pauVar3[-1] + 0xe) == 0x20)) ||
      (*(short *)(pauVar3[-1] + 0xe) == 9)))) {
    puVar5 = (ushort *)(*pauVar3 + 0xe);
    puVar4 = FUN_14003131c(puVar5,0x23);
    if ((((puVar4 != (ushort *)0x0) && (puVar4[1] < 0x21)) &&
        ((0x100000201U >> ((ulonglong)puVar4[1] & 0x3f) & 1) != 0)) &&
       (iVar8 = 0, uVar2 = uVar6, puVar5 < puVar4)) {
      do {
        uVar1 = *puVar5;
        if ((9 < (ushort)(uVar1 - 0x30)) || (86400000 < uVar2)) goto LAB_140008f0d;
        iVar8 = iVar8 + 1;
        puVar5 = puVar5 + 1;
        uVar2 = (uint)uVar1 + (uVar2 * 5 + -0x18) * 2;
      } while (puVar5 < puVar4);
      if ((iVar8 != 0) && (DAT_14007d600 = &DAT_14006ad90, -1 < (int)uVar2)) {
        DAT_14007d600 = &DAT_14006ad90;
        return uVar2;
      }
    }
  }
LAB_140008f0d:
  pauVar3 = FUN_140031398(param_1,(undefined1 (*) [16])L"#terminate#");
  if ((pauVar3 != (undefined1 (*) [16])0x0) &&
     (((pauVar3 <= param_1 || (*(short *)(pauVar3[-1] + 0xe) == 0x20)) ||
      (*(short *)(pauVar3[-1] + 0xe) == 9)))) {
    puVar5 = (ushort *)(pauVar3[1] + 6);
    puVar4 = FUN_14003131c(puVar5,0x23);
    if ((((puVar4 != (ushort *)0x0) && (puVar4[1] < 0x21)) &&
        ((0x100000201U >> ((ulonglong)puVar4[1] & 0x3f) & 1) != 0)) && (puVar5 < puVar4)) {
      do {
        uVar1 = *puVar5;
        if (9 < (ushort)(uVar1 - 0x30)) {
          return 0xffffffff;
        }
        if (86400000 < uVar6) {
          return 0xffffffff;
        }
        iVar7 = iVar7 + 1;
        puVar5 = puVar5 + 1;
        uVar6 = (uint)uVar1 + (uVar6 * 5 + -0x18) * 2;
      } while (puVar5 < puVar4);
      if (iVar7 != 0) {
        DAT_14007d600 = L"#terminate#";
        return uVar6;
      }
    }
  }
  return 0xffffffff;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008fd0 @ 140008fd0

/* WARNING: Removing unreachable block (ram,0x000140009142) */