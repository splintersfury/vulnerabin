void FUN_1400134e0(longlong param_1)

{
  code *pcVar1;
  _Facet_base *p_Var2;
  ulonglong uVar3;
  longlong lVar4;
  longlong lVar5;
  undefined1 auStack_48 [32];
  _Lockit local_28 [4];
  _Lockit local_24 [4];
  _Facet_base *local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_48;
  std::_Lockit::_Lockit(local_24,0);
  p_Var2 = DAT_14007d4e0;
  local_20 = DAT_14007d4e0;
  if (DAT_14007d650 == 0) {
    std::_Lockit::_Lockit(local_28,0);
    if (DAT_14007d650 == 0) {
      DAT_14007bdc0 = DAT_14007bdc0 + 1;
      DAT_14007d650 = (ulonglong)DAT_14007bdc0;
    }
    std::_Lockit::~_Lockit(local_28);
  }
  uVar3 = DAT_14007d650;
  lVar4 = *(longlong *)(param_1 + 8);
  if ((DAT_14007d650 < *(ulonglong *)(lVar4 + 0x18)) &&
     (*(longlong *)(*(longlong *)(lVar4 + 0x10) + DAT_14007d650 * 8) != 0)) goto LAB_1400135e7;
  lVar5 = 0;
  if (*(char *)(lVar4 + 0x24) == '\0') {
LAB_14001359c:
    if (lVar5 != 0) goto LAB_1400135e7;
  }
  else {
    lVar4 = FUN_14002d9b4();
    if (uVar3 < *(ulonglong *)(lVar4 + 0x18)) {
      lVar5 = *(longlong *)(*(longlong *)(lVar4 + 0x10) + uVar3 * 8);
      goto LAB_14001359c;
    }
  }
  if (p_Var2 == (_Facet_base *)0x0) {
    lVar4 = FUN_140013fd0((longlong *)&local_20,param_1);
    p_Var2 = local_20;
    if (lVar4 == -1) {
      FUN_140002320();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    std::_Facet_Register(local_20);
    (*(code *)PTR__guard_dispatch_icall_14005b538)(p_Var2);
    DAT_14007d4e0 = p_Var2;
  }
LAB_1400135e7:
  std::_Lockit::~_Lockit(local_24);
  FUN_14002f160(local_18 ^ (ulonglong)auStack_48);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140013620 @ 140013620