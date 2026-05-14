void FUN_140008b00(longlong param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  HMODULE hLibModule;
  code *pcVar2;
  longlong lVar3;
  undefined8 ***pppuVar4;
  ulonglong uVar5;
  undefined1 auStack_88 [32];
  undefined8 **local_68;
  undefined8 uStack_60;
  longlong local_58;
  ulonglong uStack_50;
  undefined8 *local_48;
  undefined **local_40;
  undefined8 **local_38;
  undefined8 uStack_30;
  longlong local_28;
  ulonglong uStack_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_88;
  puVar1 = *(undefined8 **)(param_1 + 0x20);
  pppuVar4 = (undefined8 ***)0x0;
  local_38 = (undefined8 ***)0x0;
  local_28 = 0;
  uStack_20 = 7;
  if (puVar1 == (undefined8 *)0x0) {
    local_48 = (undefined8 *)0x0;
    local_40 = &PTR_vftable_14007ac70;
    FUN_1400067c0(&local_68,&local_48,param_3);
    local_38 = local_68;
    uStack_30 = uStack_60;
    local_28 = local_58;
    uStack_20 = uStack_50;
  }
  else {
    uVar5 = 0xffffffffffffffff;
    do {
      uVar5 = uVar5 + 1;
    } while (*(short *)((longlong)puVar1 + uVar5 * 2) != 0);
    FUN_140010340((longlong *)&local_38,puVar1,uVar5);
  }
  local_48 = (undefined8 *)0x0;
  if ((local_28 != 0) && (pppuVar4 = &local_38, 7 < uStack_20)) {
    pppuVar4 = (undefined8 ***)local_38;
  }
  FUN_140006fc0(&local_48,pppuVar4);
  puVar1 = local_48;
  if (local_48 == (undefined8 *)0x0) {
    if (uStack_20 < 8) goto LAB_140008c04;
    if (0xfff < uStack_20 * 2 + 2) {
      lVar3 = (longlong)local_38 - (longlong)local_38[-1];
joined_r0x000140008cb8:
      if (0x1f < lVar3 - 8U) {
        FUN_140035d28();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
    }
  }
  else {
    (*(code *)PTR__guard_dispatch_icall_14005b538)();
    hLibModule = (HMODULE)*puVar1;
    if (hLibModule != (HMODULE)0x0) {
      FreeLibrary(hLibModule);
      *puVar1 = 0;
    }
    FUN_14002f180();
    if (uStack_20 < 8) goto LAB_140008c04;
    if (0xfff < uStack_20 * 2 + 2) {
      lVar3 = (longlong)local_38 - (longlong)local_38[-1];
      goto joined_r0x000140008cb8;
    }
  }
  FUN_14002f180();
LAB_140008c04:
  if ((*(char *)(param_1 + 0x68) != '\0') && (lVar3 = *(longlong *)(param_1 + 0x60), lVar3 != 0)) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar3,lVar3 != param_1 + 0x28);
    *(undefined8 *)(param_1 + 0x60) = 0;
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_88);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140008cd0 @ 140008cd0