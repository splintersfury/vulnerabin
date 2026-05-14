void __fastcall FUN_100187a0(int param_1)

{
  int *piVar1;
  short *psVar2;
  wchar_t *pwVar3;
  int iVar4;
  _Facet_base *p_Var5;
  int *piVar6;
  _Ctypevec *p_Var7;
  undefined4 *puVar8;
  _Locinfo local_84 [52];
  _Ctypevec local_50;
  int *local_38;
  undefined1 local_31;
  _Lockit local_30 [4];
  _Facet_base *local_2c;
  uint local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  uint local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004f3ec;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  piVar1 = *(int **)(*(int *)(param_1 + 0x30) + 4);
  local_38 = piVar1;
  (**(code **)(*piVar1 + 4))(local_24);
  local_14 = 0;
  std::_Lockit::_Lockit(local_30,0);
  local_14 = CONCAT31(local_14._1_3_,1);
  local_2c = DAT_1006b62c;
  local_28 = DAT_1006a8d8;
  if (DAT_1006a8d8 == 0) {
    std::_Lockit::_Lockit((_Lockit *)&local_28,0);
    if (DAT_1006a8d8 == 0) {
      DAT_1006a8c0 = DAT_1006a8c0 + 1;
      DAT_1006a8d8 = DAT_1006a8c0;
    }
    FUN_1002c986((int *)&local_28);
  }
  local_28 = DAT_1006a8d8;
  if (DAT_1006a8d8 < (uint)piVar1[3]) {
    p_Var5 = *(_Facet_base **)(piVar1[2] + DAT_1006a8d8 * 4);
    if (p_Var5 != (_Facet_base *)0x0) goto LAB_100188f5;
  }
  else {
    p_Var5 = (_Facet_base *)0x0;
  }
  if ((char)piVar1[5] == '\0') {
LAB_1001887b:
    if (p_Var5 != (_Facet_base *)0x0) goto LAB_100188f5;
  }
  else {
    iVar4 = FUN_1002cb0b();
    if (local_28 < *(uint *)(iVar4 + 0xc)) {
      p_Var5 = *(_Facet_base **)(*(int *)(iVar4 + 8) + local_28 * 4);
      goto LAB_1001887b;
    }
  }
  p_Var5 = local_2c;
  if (local_2c == (_Facet_base *)0x0) {
    p_Var5 = (_Facet_base *)operator_new(0x18);
    local_14._0_1_ = 2;
    piVar6 = (int *)piVar1[6];
    if (piVar6 == (int *)0x0) {
      piVar6 = piVar1 + 7;
    }
    local_2c = p_Var5;
    FUN_10002540(local_84,(char *)piVar6);
    *(undefined4 *)(p_Var5 + 4) = 0;
    *(undefined ***)p_Var5 = std::ctype<char>::vftable;
    p_Var7 = __Getctype(&local_50);
    psVar2 = p_Var7->_Table;
    iVar4 = p_Var7->_Delfl;
    pwVar3 = p_Var7->_LocaleName;
    *(uint *)(p_Var5 + 8) = p_Var7->_Page;
    *(short **)(p_Var5 + 0xc) = psVar2;
    *(int *)(p_Var5 + 0x10) = iVar4;
    *(wchar_t **)(p_Var5 + 0x14) = pwVar3;
    FUN_100025f0(local_84);
    local_14 = CONCAT31(local_14._1_3_,3);
    local_2c = p_Var5;
    std::_Facet_Register(p_Var5);
    (**(code **)(*(int *)p_Var5 + 4))();
    DAT_1006b62c = p_Var5;
  }
LAB_100188f5:
  local_14 = local_14 & 0xffffff00;
  FUN_1002c986((int *)local_30);
  local_31 = (**(code **)(*(int *)p_Var5 + 0x20))(0x20);
  puVar8 = (undefined4 *)(**(code **)(*piVar1 + 8))();
  if (puVar8 != (undefined4 *)0x0) {
    (**(code **)*puVar8)(1);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018950 @ 10018950