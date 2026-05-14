void __cdecl FUN_10006410(_Facet_base *param_1)

{
  short *psVar1;
  wchar_t *pwVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int iVar7;
  _Facet_base *p_Var8;
  char *pcVar9;
  _Ctypevec *p_Var10;
  _Cvtvec *p_Var11;
  int iVar12;
  _Cvtvec local_b0;
  _Locinfo local_7c [52];
  _Ctypevec local_48;
  _Facet_base *local_34;
  _Lockit local_30 [4];
  _Lockit local_2c [4];
  _Facet_base *local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004de24;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_28 = param_1;
  std::_Lockit::_Lockit(local_30,0);
  local_14 = 0;
  local_34 = DAT_1006b608;
  if (DAT_1006a8d4 == 0) {
    std::_Lockit::_Lockit(local_2c,0);
    if (DAT_1006a8d4 == 0) {
      DAT_1006a8c0 = DAT_1006a8c0 + 1;
      DAT_1006a8d4 = DAT_1006a8c0;
    }
    FUN_1002c986((int *)local_2c);
  }
  uVar3 = DAT_1006a8d4;
  iVar7 = *(int *)(param_1 + 4);
  if ((DAT_1006a8d4 < *(uint *)(iVar7 + 0xc)) &&
     (*(int *)(*(int *)(iVar7 + 8) + DAT_1006a8d4 * 4) != 0)) goto LAB_10006599;
  iVar12 = 0;
  if (*(char *)(iVar7 + 0x14) == '\0') {
LAB_100064d9:
    if (iVar12 != 0) goto LAB_10006599;
  }
  else {
    iVar7 = FUN_1002cb0b();
    if (uVar3 < *(uint *)(iVar7 + 0xc)) {
      iVar12 = *(int *)(*(int *)(iVar7 + 8) + uVar3 * 4);
      goto LAB_100064d9;
    }
  }
  if (local_34 == (_Facet_base *)0x0) {
    p_Var8 = (_Facet_base *)operator_new(0x44);
    local_14._0_1_ = 1;
    iVar7 = *(int *)(local_28 + 4);
    if (iVar7 == 0) {
      pcVar9 = "";
    }
    else {
      pcVar9 = *(char **)(iVar7 + 0x18);
      if (pcVar9 == (char *)0x0) {
        pcVar9 = (char *)(iVar7 + 0x1c);
      }
    }
    local_34 = p_Var8;
    FUN_10002540(local_7c,pcVar9);
    *(undefined4 *)(p_Var8 + 4) = 0;
    *(undefined ***)p_Var8 = std::ctype<wchar_t>::vftable;
    p_Var10 = __Getctype(&local_48);
    psVar1 = p_Var10->_Table;
    iVar7 = p_Var10->_Delfl;
    pwVar2 = p_Var10->_LocaleName;
    *(uint *)(p_Var8 + 8) = p_Var10->_Page;
    *(short **)(p_Var8 + 0xc) = psVar1;
    *(int *)(p_Var8 + 0x10) = iVar7;
    *(wchar_t **)(p_Var8 + 0x14) = pwVar2;
    p_Var11 = __Getcvt(&local_b0);
    uVar3 = p_Var11->_Mbcurmax;
    iVar7 = p_Var11->_Isclocale;
    uVar4 = *(undefined4 *)p_Var11->_Isleadbyte;
    *(uint *)(p_Var8 + 0x18) = p_Var11->_Page;
    *(uint *)(p_Var8 + 0x1c) = uVar3;
    *(int *)(p_Var8 + 0x20) = iVar7;
    *(undefined4 *)(p_Var8 + 0x24) = uVar4;
    uVar4 = *(undefined4 *)(p_Var11->_Isleadbyte + 8);
    uVar5 = *(undefined4 *)(p_Var11->_Isleadbyte + 0xc);
    uVar6 = *(undefined4 *)(p_Var11->_Isleadbyte + 0x10);
    *(undefined4 *)(p_Var8 + 0x28) = *(undefined4 *)(p_Var11->_Isleadbyte + 4);
    *(undefined4 *)(p_Var8 + 0x2c) = uVar4;
    *(undefined4 *)(p_Var8 + 0x30) = uVar5;
    *(undefined4 *)(p_Var8 + 0x34) = uVar6;
    *(undefined8 *)(p_Var8 + 0x38) = *(undefined8 *)(p_Var11->_Isleadbyte + 0x14);
    *(undefined4 *)(p_Var8 + 0x40) = *(undefined4 *)(p_Var11->_Isleadbyte + 0x1c);
    FUN_100025f0(local_7c);
    local_14 = CONCAT31(local_14._1_3_,2);
    local_28 = p_Var8;
    std::_Facet_Register(p_Var8);
    (**(code **)(*(int *)p_Var8 + 4))();
    DAT_1006b608 = p_Var8;
  }
LAB_10006599:
  FUN_1002c986((int *)local_30);
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_100065d0 @ 100065d0