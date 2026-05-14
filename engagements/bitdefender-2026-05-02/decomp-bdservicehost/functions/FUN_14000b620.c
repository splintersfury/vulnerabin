void FUN_14000b620(LPCWSTR param_1)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  uint uVar4;
  LPCWSTR pWVar5;
  undefined1 auStack_58 [32];
  undefined8 local_38 [2];
  uint local_28;
  int local_24;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_58;
  pWVar5 = param_1;
  if (7 < *(ulonglong *)(param_1 + 0xc)) {
    pWVar5 = *(LPCWSTR *)param_1;
  }
  iVar2 = __std_fs_get_stats(pWVar5,local_38,6,0xffffffff);
  if (iVar2 == 0) {
    if ((local_28 >> 10 & 1) == 0) {
LAB_14000b6b1:
      uVar4 = (local_28 & 0x10 | 0x20) >> 4;
    }
    else if (local_24 == -0x5ffffff4) {
      uVar4 = 4;
    }
    else {
      if (local_24 != -0x5ffffffd) goto LAB_14000b6b1;
      uVar4 = 10;
    }
LAB_14000b678:
    if (((uVar4 - 2 & 0xfffffff5) == 0) && (uVar4 != 0xc)) {
      pWVar5 = param_1;
      if (7 < *(ulonglong *)(param_1 + 0xc)) {
        pWVar5 = *(LPCWSTR *)param_1;
      }
      uVar3 = FUN_14002e910(pWVar5);
      iVar2 = (int)((ulonglong)uVar3 >> 0x20);
      if (iVar2 != 0) {
        FUN_140005ed0((undefined8 *)"remove",iVar2,(undefined8 *)param_1);
        goto LAB_14000b723;
      }
    }
    pWVar5 = param_1;
    if (7 < *(ulonglong *)(param_1 + 0xc)) {
      pWVar5 = *(LPCWSTR *)param_1;
    }
    uVar3 = __std_fs_create_directory(pWVar5);
    iVar2 = (int)((ulonglong)uVar3 >> 0x20);
    if (iVar2 == 0) {
      FUN_14002f160(local_18 ^ (ulonglong)auStack_58);
      return;
    }
  }
  else {
    if ((((iVar2 == 2) || (iVar2 == 3)) || (iVar2 == 0x35)) || (iVar2 == 0x7b)) {
      uVar4 = 1;
    }
    else {
      uVar4 = 0;
    }
    if ((uVar4 - 1 & 0xfffffff7) == 0) goto LAB_14000b678;
LAB_14000b723:
    iVar2 = FUN_140005ed0((undefined8 *)"symlink_status",iVar2,(undefined8 *)param_1);
  }
  FUN_140005ed0((undefined8 *)"create_directory",iVar2,(undefined8 *)param_1);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000b750 @ 14000b750

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */