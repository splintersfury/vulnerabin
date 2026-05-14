void FUN_14001f7c0(longlong param_1)

{
  code *pcVar1;
  ulonglong uVar2;
  _Facet_base *p_Var3;
  longlong lVar4;
  longlong lVar5;
  _Facet_base *p_Var6;
  undefined1 auStack_58 [32];
  undefined1 local_38 [8];
  longlong local_30;
  _Lockit local_28 [4];
  _Lockit local_24 [4];
  _Facet_base *local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_58;
  lVar5 = *(longlong *)(*(longlong *)(param_1 + 0x40) + 8);
  local_30 = lVar5;
  (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5);
  std::_Lockit::_Lockit(local_24,0);
  p_Var3 = DAT_14007d528;
  local_20 = DAT_14007d528;
  if (DAT_14007bdd8 == 0) {
    std::_Lockit::_Lockit(local_28,0);
    if (DAT_14007bdd8 == 0) {
      DAT_14007bdc0 = DAT_14007bdc0 + 1;
      DAT_14007bdd8 = (ulonglong)DAT_14007bdc0;
    }
    std::_Lockit::~_Lockit(local_28);
  }
  uVar2 = DAT_14007bdd8;
  if (DAT_14007bdd8 < *(ulonglong *)(lVar5 + 0x18)) {
    p_Var6 = *(_Facet_base **)(*(longlong *)(lVar5 + 0x10) + DAT_14007bdd8 * 8);
    if (p_Var6 != (_Facet_base *)0x0) goto LAB_14001f8e4;
  }
  else {
    p_Var6 = (_Facet_base *)0x0;
  }
  if (*(char *)(lVar5 + 0x24) == '\0') {
LAB_14001f893:
    if (p_Var6 != (_Facet_base *)0x0) goto LAB_14001f8e4;
  }
  else {
    lVar4 = FUN_14002d9b4();
    if (uVar2 < *(ulonglong *)(lVar4 + 0x18)) {
      p_Var6 = *(_Facet_base **)(*(longlong *)(lVar4 + 0x10) + uVar2 * 8);
      goto LAB_14001f893;
    }
  }
  p_Var6 = p_Var3;
  if (p_Var3 == (_Facet_base *)0x0) {
    lVar4 = FUN_1400196b0((longlong *)&local_20,(longlong)local_38);
    p_Var6 = local_20;
    if (lVar4 == -1) {
      FUN_140002320();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    std::_Facet_Register(local_20);
    (*(code *)PTR__guard_dispatch_icall_14005b538)(p_Var6);
    DAT_14007d528 = p_Var6;
  }
LAB_14001f8e4:
  std::_Lockit::~_Lockit(local_24);
  (*(code *)PTR__guard_dispatch_icall_14005b538)(p_Var6,0x20);
  lVar5 = (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5);
  if (lVar5 != 0) {
    (*(code *)PTR__guard_dispatch_icall_14005b538)(lVar5,1);
  }
  FUN_14002f160(local_18 ^ (ulonglong)auStack_58);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001f960 @ 14001f960