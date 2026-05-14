void FUN_140013c80(longlong param_1)

{
  code *pcVar1;
  ulonglong uVar2;
  _Facet_base *p_Var3;
  longlong lVar4;
  longlong lVar5;
  undefined1 auStack_48 [32];
  _Lockit local_28 [4];
  _Lockit local_24 [4];
  _Facet_base *local_20;
  ulonglong local_18;
  
  local_18 = DAT_14007a060 ^ (ulonglong)auStack_48;
  std::_Lockit::_Lockit(local_24,0);
  p_Var3 = DAT_14007d4d8;
  local_20 = DAT_14007d4d8;
  if (DAT_14007bdd0 == 0) {
    std::_Lockit::_Lockit(local_28,0);
    if (DAT_14007bdd0 == 0) {
      DAT_14007bdc0 = DAT_14007bdc0 + 1;
      DAT_14007bdd0 = (ulonglong)DAT_14007bdc0;
    }
    std::_Lockit::~_Lockit(local_28);
  }
  uVar2 = DAT_14007bdd0;
  lVar4 = *(longlong *)(param_1 + 8);
  if ((DAT_14007bdd0 < *(ulonglong *)(lVar4 + 0x18)) &&
     (*(longlong *)(*(longlong *)(lVar4 + 0x10) + DAT_14007bdd0 * 8) != 0)) goto LAB_140013d87;
  lVar5 = 0;
  if (*(char *)(lVar4 + 0x24) == '\0') {
LAB_140013d3c:
    if (lVar5 != 0) goto LAB_140013d87;
  }
  else {
    lVar4 = FUN_14002d9b4();
    if (uVar2 < *(ulonglong *)(lVar4 + 0x18)) {
      lVar5 = *(longlong *)(*(longlong *)(lVar4 + 0x10) + uVar2 * 8);
      goto LAB_140013d3c;
    }
  }
  if (p_Var3 == (_Facet_base *)0x0) {
    lVar4 = FUN_1400025d0((longlong *)&local_20,param_1);
    p_Var3 = local_20;
    if (lVar4 == -1) {
      FUN_140002320();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    std::_Facet_Register(local_20);
    (*(code *)PTR__guard_dispatch_icall_14005b538)(p_Var3);
    DAT_14007d4d8 = p_Var3;
  }
LAB_140013d87:
  std::_Lockit::~_Lockit(local_24);
  FUN_14002f160(local_18 ^ (ulonglong)auStack_48);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_140013dc0 @ 140013dc0