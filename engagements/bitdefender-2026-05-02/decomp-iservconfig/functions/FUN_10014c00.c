void __cdecl FUN_10014c00(_Facet_base *param_1)

{
  uint uVar1;
  int iVar2;
  _Facet_base *p_Var3;
  char *pcVar4;
  int iVar5;
  _Locinfo local_54 [52];
  _Lockit local_20 [4];
  _Facet_base *local_1c;
  _Facet_base *local_18;
  uint local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004e0c4;
  local_10 = ExceptionList;
  local_14 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_1c = param_1;
  std::_Lockit::_Lockit(local_20,0);
  p_Var3 = DAT_1006b628;
  local_8 = 0;
  if (DAT_1006b6b8 == 0) {
    std::_Lockit::_Lockit((_Lockit *)&local_18,0);
    if (DAT_1006b6b8 == 0) {
      DAT_1006a8c0 = DAT_1006a8c0 + 1;
      DAT_1006b6b8 = DAT_1006a8c0;
    }
    FUN_1002c986((int *)&local_18);
  }
  uVar1 = DAT_1006b6b8;
  iVar2 = *(int *)(param_1 + 4);
  if ((DAT_1006b6b8 < *(uint *)(iVar2 + 0xc)) &&
     (*(int *)(*(int *)(iVar2 + 8) + DAT_1006b6b8 * 4) != 0)) goto LAB_10014d26;
  iVar5 = 0;
  if (*(char *)(iVar2 + 0x14) == '\0') {
LAB_10014cb1:
    if (iVar5 != 0) goto LAB_10014d26;
  }
  else {
    iVar2 = FUN_1002cb0b();
    if (uVar1 < *(uint *)(iVar2 + 0xc)) {
      iVar5 = *(int *)(*(int *)(iVar2 + 8) + uVar1 * 4);
      goto LAB_10014cb1;
    }
  }
  if (p_Var3 == (_Facet_base *)0x0) {
    p_Var3 = (_Facet_base *)operator_new(8);
    local_8._0_1_ = 1;
    iVar2 = *(int *)(local_1c + 4);
    if (iVar2 == 0) {
      pcVar4 = "";
    }
    else {
      pcVar4 = *(char **)(iVar2 + 0x18);
      if (pcVar4 == (char *)0x0) {
        pcVar4 = (char *)(iVar2 + 0x1c);
      }
    }
    local_18 = p_Var3;
    FUN_10002540(local_54,pcVar4);
    *(undefined4 *)(p_Var3 + 4) = 0;
    *(undefined ***)p_Var3 = std::codecvt<char,char,struct__Mbstatet>::vftable;
    FUN_100025f0(local_54);
    local_8 = CONCAT31(local_8._1_3_,2);
    local_1c = p_Var3;
    std::_Facet_Register(p_Var3);
    (**(code **)(*(int *)p_Var3 + 4))();
    DAT_1006b628 = p_Var3;
  }
LAB_10014d26:
  FUN_1002c986((int *)local_20);
  ExceptionList = local_10;
  FUN_1002e315(local_14 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10014d50 @ 10014d50