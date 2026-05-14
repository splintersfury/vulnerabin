int * __thiscall FUN_10017d20(void *this,wchar_t *param_1)

{
  basic_filebuf<char,struct_std::char_traits<char>_> *pbVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int *piVar4;
  undefined1 uVar5;
  undefined8 *puVar6;
  _Locimp *p_Var7;
  int iVar8;
  codecvt<char,char,struct__Mbstatet> *pcVar9;
  undefined4 *puVar10;
  void *pvVar11;
  _Facet_base local_28 [4];
  wchar_t *local_24;
  undefined4 *local_20;
  basic_filebuf<char,struct_std::char_traits<char>_> *local_1c;
  int *local_18;
  basic_filebuf<char,struct_std::char_traits<char>_> *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004f2df;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_1005e6d8;
  local_24 = param_1;
  *(undefined4 *)((int)this + 0x78) = 0;
  *(undefined4 *)((int)this + 0x98) = 0;
  *(undefined4 *)((int)this + 0x9c) = 0;
  *(undefined4 *)((int)this + 0xa0) = 0;
  *(undefined ***)((int)this + 0x70) = std::basic_ios<char,struct_std::char_traits<char>_>::vftable;
  local_8 = 0;
                    /* WARNING: Load size is inaccurate */
  *(undefined ***)((int)this + *(int *)(*this + 4)) =
       std::basic_istream<char,struct_std::char_traits<char>_>::vftable;
                    /* WARNING: Load size is inaccurate */
  *(int *)(*(int *)(*this + 4) + -4 + (int)this) = *(int *)(*this + 4) + -0x18;
                    /* WARNING: Load size is inaccurate */
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  pvVar11 = (void *)(*(int *)(*this + 4) + (int)this);
  local_1c = (basic_filebuf<char,struct_std::char_traits<char>_> *)this;
  local_18 = (int *)this;
  FUN_10002c40(pvVar11);
  pbVar1 = (basic_filebuf<char,struct_std::char_traits<char>_> *)((int)this + 0x10);
  *(undefined4 *)((int)pvVar11 + 0x3c) = 0;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)((int)pvVar11 + 0x38) = pbVar1;
  local_14 = pbVar1;
  uVar5 = FUN_100187a0((int)pvVar11);
  *(undefined1 *)((int)pvVar11 + 0x40) = uVar5;
  if (*(int *)((int)pvVar11 + 0x38) == 0) {
    FUN_10002bd0(pvVar11,*(uint *)((int)pvVar11 + 0xc) | 4,'\0');
  }
  local_8 = 2;
                    /* WARNING: Load size is inaccurate */
  *(undefined ***)((int)this + *(int *)(*this + 4)) =
       std::basic_ifstream<char,struct_std::char_traits<char>_>::vftable;
                    /* WARNING: Load size is inaccurate */
  *(int *)(*(int *)(*this + 4) + -4 + (int)this) = *(int *)(*this + 4) + -0x70;
  *(undefined ***)pbVar1 = std::basic_streambuf<char,struct_std::char_traits<char>_>::vftable;
  local_1c = pbVar1;
  puVar6 = (undefined8 *)operator_new(8);
  *puVar6 = 0;
  local_8._0_1_ = 3;
  p_Var7 = std::locale::_Init(true);
  pbVar1 = local_14;
  *(_Locimp **)((int)puVar6 + 4) = p_Var7;
  local_20 = (undefined4 *)((int)this + 0x14);
  local_1c = (basic_filebuf<char,struct_std::char_traits<char>_> *)((int)this + 0x18);
  *(undefined8 **)((int)this + 0x44) = puVar6;
  *(undefined ***)local_14 = std::basic_filebuf<char,struct_std::char_traits<char>_>::vftable;
  local_14[0x48] = (basic_filebuf<char,struct_std::char_traits<char>_>)0x0;
  local_14[0x3d] = (basic_filebuf<char,struct_std::char_traits<char>_>)0x0;
  *(undefined4 **)(local_14 + 0xc) = local_20;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(local_14 + 0x20) = local_14 + 0x18;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(local_14 + 0x30) = local_14 + 0x28;
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(local_14 + 0x10) = local_1c;
  *(undefined4 **)(local_14 + 0x1c) = (undefined4 *)((int)this + 0x24);
  *(basic_filebuf<char,struct_std::char_traits<char>_> **)(local_14 + 0x2c) = local_14 + 0x24;
  *(undefined4 *)local_1c = 0;
  *(undefined4 *)(local_14 + 0x18) = 0;
  uVar3 = DAT_1006b634;
  *(undefined4 *)(local_14 + 0x28) = 0;
  uVar2 = DAT_1006b630;
  *local_20 = 0;
  *(undefined4 *)((int)this + 0x24) = 0;
  *(undefined4 *)(local_14 + 0x24) = 0;
  *(undefined4 *)(local_14 + 0x4c) = 0;
  *(undefined4 *)(local_14 + 0x40) = uVar2;
  *(undefined4 *)(local_14 + 0x44) = uVar3;
  *(undefined4 *)(local_14 + 0x38) = 0;
  local_8._0_1_ = 4;
  uVar5 = (undefined1)local_8;
  local_8._0_1_ = 4;
  if (*(int *)(local_14 + 0x4c) == 0) {
    iVar8 = FUN_1002db84(local_24,1,0x40);
    uVar5 = (undefined1)local_8;
    if (iVar8 != 0) {
      FUN_10011a70(pbVar1,iVar8,1);
      local_24 = *(wchar_t **)(*(int *)(pbVar1 + 0x34) + 4);
      (**(code **)(*(int *)local_24 + 4))();
      local_8 = CONCAT31(local_8._1_3_,5);
      pcVar9 = (codecvt<char,char,struct__Mbstatet> *)FUN_10014c00(local_28);
      std::basic_filebuf<char,struct_std::char_traits<char>_>::_Initcvt(pbVar1,pcVar9);
      if (local_24 != (wchar_t *)0x0) {
        puVar10 = (undefined4 *)(**(code **)(*(int *)local_24 + 8))();
        if (puVar10 != (undefined4 *)0x0) {
          (**(code **)*puVar10)(1);
        }
      }
      ExceptionList = local_10;
      return local_18;
    }
  }
  local_8._0_1_ = uVar5;
  piVar4 = local_18;
  pvVar11 = (void *)(*(int *)(*local_18 + 4) + (int)local_18);
  FUN_10002bd0(pvVar11,(uint)(*(int *)((int)pvVar11 + 0x38) == 0) * 4 + 2 |
                       *(uint *)((int)pvVar11 + 0xc),'\0');
  ExceptionList = local_10;
  return piVar4;
}


// FUNCTION_END

// FUNCTION_START: FUN_10017fa0 @ 10017fa0