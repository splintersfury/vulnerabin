void __cdecl FUN_10008670(int param_1)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  _Facet_base *p_Var4;
  char *pcVar5;
  _Cvtvec *p_Var6;
  undefined1 *puVar7;
  undefined4 uVar8;
  int iVar9;
  _Cvtvec local_108;
  _Cvtvec local_d8;
  _Locinfo local_a8 [52];
  _Cvtvec local_74;
  mbstate_t local_48 [2];
  _Lockit local_40 [4];
  mbstate_t local_3c;
  _Facet_base *p_Stack_38;
  _Facet_base *local_34;
  wchar_t local_30 [2];
  char local_2c [4];
  char local_28 [4];
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004e140;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  _local_3c = CONCAT44(param_1,local_3c);
  local_30[0] = L'\0';
  local_30[1] = L'\0';
  std::_Lockit::_Lockit(local_40,0);
  local_14 = 0;
  local_34 = DAT_1006b600;
  if (DAT_1006b6b4 == 0) {
    std::_Lockit::_Lockit((_Lockit *)local_30,0);
    if (DAT_1006b6b4 == 0) {
      DAT_1006a8c0 = DAT_1006a8c0 + 1;
      DAT_1006b6b4 = DAT_1006a8c0;
    }
    FUN_1002c986((int *)local_30);
  }
  uVar2 = DAT_1006b6b4;
  iVar3 = *(int *)(param_1 + 4);
  if ((DAT_1006b6b4 < *(uint *)(iVar3 + 0xc)) &&
     (*(int *)(*(int *)(iVar3 + 8) + DAT_1006b6b4 * 4) != 0)) goto LAB_100088f3;
  iVar9 = 0;
  if (*(char *)(iVar3 + 0x14) == '\0') {
LAB_10008740:
    if (iVar9 != 0) goto LAB_100088f3;
  }
  else {
    iVar3 = FUN_1002cb0b();
    if (uVar2 < *(uint *)(iVar3 + 0xc)) {
      iVar9 = *(int *)(*(int *)(iVar3 + 8) + uVar2 * 4);
      goto LAB_10008740;
    }
  }
  if (local_34 == (_Facet_base *)0x0) {
    p_Var4 = (_Facet_base *)operator_new(0x18);
    local_14 = CONCAT31(local_14._1_3_,1);
    *(undefined4 *)p_Var4 = 0;
    *(undefined4 *)(p_Var4 + 4) = 0;
    *(undefined4 *)(p_Var4 + 8) = 0;
    *(undefined4 *)(p_Var4 + 0xc) = 0;
    *(undefined8 *)(p_Var4 + 0x10) = 0;
    iVar3 = *(int *)((int)p_Stack_38 + 4);
    if (iVar3 == 0) {
      pcVar5 = "";
    }
    else {
      pcVar5 = *(char **)(iVar3 + 0x18);
      if (pcVar5 == (char *)0x0) {
        pcVar5 = (char *)(iVar3 + 0x1c);
      }
    }
    local_34 = p_Var4;
    FUN_10002540(local_a8,pcVar5);
    local_30[0] = L'\x01';
    local_30[1] = L'\0';
    *(undefined4 *)(p_Var4 + 4) = 0;
    local_14 = 3;
    *(undefined ***)p_Var4 = std::numpunct<wchar_t>::vftable;
    _localeconv();
    p_Var6 = __Getcvt(&local_d8);
    _local_3c = CONCAT44(p_Var4,local_3c);
    local_74._Page = p_Var6->_Page;
    local_74._Mbcurmax = p_Var6->_Mbcurmax;
    local_74._Isclocale = p_Var6->_Isclocale;
    local_74._Isleadbyte._0_4_ = *(undefined4 *)p_Var6->_Isleadbyte;
    local_74._Isleadbyte._4_4_ = *(undefined4 *)(p_Var6->_Isleadbyte + 4);
    local_74._Isleadbyte._8_4_ = *(undefined4 *)(p_Var6->_Isleadbyte + 8);
    local_74._Isleadbyte._12_4_ = *(undefined4 *)(p_Var6->_Isleadbyte + 0xc);
    local_74._Isleadbyte._16_4_ = *(undefined4 *)(p_Var6->_Isleadbyte + 0x10);
    local_74._Isleadbyte._20_8_ = *(undefined8 *)(p_Var6->_Isleadbyte + 0x14);
    local_74._Isleadbyte._28_4_ = *(undefined4 *)(p_Var6->_Isleadbyte + 0x1c);
    *(undefined4 *)(p_Var4 + 8) = 0;
    *(undefined4 *)(p_Var4 + 0x10) = 0;
    *(undefined4 *)(p_Var4 + 0x14) = 0;
    local_14 = CONCAT31(local_14._1_3_,4);
    __Getcvt(&local_108);
    puVar7 = (undefined1 *)FUN_1003310d(1,1);
    if (puVar7 == (undefined1 *)0x0) {
      FUN_1002c81a();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    *puVar7 = 0;
    *(undefined1 **)(p_Var4 + 8) = puVar7;
    uVar8 = FUN_10002730("false",0,&local_74);
    *(undefined4 *)(p_Var4 + 0x10) = uVar8;
    uVar8 = FUN_10002730("true",0,&local_74);
    *(undefined4 *)(p_Var4 + 0x14) = uVar8;
    local_28[0] = '.';
    local_34 = (_Facet_base *)0x0;
    _local_3c = 0;
    __Mbrtowc((wchar_t *)&local_34,local_28,1,&local_3c,&local_74);
    *(undefined2 *)(p_Var4 + 0xc) = local_34._0_2_;
    local_2c[0] = ',';
    local_30[0] = L'\0';
    local_30[1] = L'\0';
    local_48[0] = 0;
    local_48[1] = 0;
    __Mbrtowc(local_30,local_2c,1,local_48,&local_74);
    *(wchar_t *)(p_Var4 + 0xe) = local_30[0];
    local_14 = 0;
    FUN_100025f0(local_a8);
    _local_3c = CONCAT44(p_Var4,local_3c);
    local_14 = CONCAT31(local_14._1_3_,6);
    std::_Facet_Register(p_Var4);
    (**(code **)(*(int *)p_Var4 + 4))();
    DAT_1006b600 = p_Var4;
  }
LAB_100088f3:
  FUN_1002c986((int *)local_40);
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10008930 @ 10008930