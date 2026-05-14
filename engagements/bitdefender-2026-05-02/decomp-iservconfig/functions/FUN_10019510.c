void __thiscall
FUN_10019510(void *this,undefined4 *param_1,char *param_2,int *param_3,int *param_4,int param_5)

{
  void *pvVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  void *pvVar5;
  int *piVar6;
  int *piVar7;
  uint *puVar8;
  int extraout_EDX;
  int unaff_EBP;
  uint local_c0 [6];
  undefined1 local_a8 [24];
  int local_90 [7];
  int local_74 [7];
  uint local_58 [2];
  char local_50 [8];
  int local_48;
  int local_44;
  int *local_3c;
  int *local_38;
  int *local_34;
  int local_30;
  undefined4 *local_2c;
  int *local_28;
  uint local_24;
  undefined1 *puStack_20;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  puStack_20 = &stack0xfffffffc;
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004f59b;
  local_1c = ExceptionList;
  local_24 = DAT_10069054 ^ (uint)&stack0xfffffff0;
  ExceptionList = &local_1c;
  local_2c = param_1;
  if ((char *)this != param_2) {
    FUN_10005690(local_58,(uint *)"iterator does not fit current value");
    local_14 = 0;
    FUN_1000abb0(local_74,0xca,local_58);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(local_74,&DAT_1006750c);
  }
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  puStack_20 = &stack0xfffffffc;
  FUN_100184e0(this,param_1);
                    /* WARNING: Load size is inaccurate */
  switch(*this) {
  case '\x01':
    local_28 = param_3;
    std::
    _Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
    ::operator++((_Tree_unchecked_const_iterator<class_std::_Tree_val<struct_std::_Tree_simple_types<unsigned_int>_>,struct_std::_Iterator_base0>
                  *)&local_28);
    piVar6 = FUN_1001b8f0(*(void **)((int)this + 8),param_3);
    FUN_1000e760((char *)(piVar6 + 10));
    if (0xf < (uint)piVar6[9]) {
      pvVar1 = (void *)piVar6[4];
      pvVar5 = pvVar1;
      if ((0xfff < piVar6[9] + 1U) &&
         (pvVar5 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar5)))) {
LAB_100197f1:
        FUN_10032f7f();
        if (-1 < unaff_EBP + extraout_EDX) {
          cRam00fc45c7 = cRam00fc45c7 + -0x39;
          cRam00fc4581 = cRam00fc4581 + (char)extraout_EDX;
          return;
        }
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      FUN_1002e346(pvVar5);
    }
    piVar6[8] = 0;
    piVar6[9] = 0xf;
    *(undefined1 *)(piVar6 + 4) = 0;
    FUN_1002e346(piVar6);
    local_2c[1] = local_28;
    break;
  case '\x02':
    local_38 = (int *)(*(int *)((int)this + 8) + 4);
    local_3c = param_4;
    piVar7 = (int *)*local_38;
    piVar6 = param_4 + 4;
    local_34 = piVar7;
    if (piVar6 != piVar7) {
      local_28 = param_4;
      do {
        local_30 = piVar6[3];
        iVar4 = *piVar6;
        iVar2 = piVar6[2];
        *(undefined1 *)piVar6 = 0;
        piVar6[2] = 0;
        piVar6[3] = 0;
        local_50[0] = (char)*local_28;
        *(char *)local_28 = (char)iVar4;
        local_48 = local_28[2];
        local_44 = local_28[3];
        local_28[2] = iVar2;
        local_28[3] = local_30;
        FUN_1000e760(local_50);
        piVar6 = piVar6 + 4;
        local_28 = local_28 + 4;
      } while (piVar6 != local_34);
      piVar7 = (int *)*local_38;
    }
    piVar6 = local_38;
    FUN_1000e760((char *)(piVar7 + -4));
    *piVar6 = *piVar6 + -0x10;
    local_2c[2] = local_3c;
    break;
  case '\x03':
  case '\x04':
  case '\x05':
  case '\x06':
  case '\a':
    if (param_5 != 0) {
      FUN_10005690(local_58,(uint *)"iterator out of range");
      local_14 = 1;
      FUN_1000abb0(local_74,0xcd,local_58);
                    /* WARNING: Subroutine does not return */
      __CxxThrowException_8(local_74,&DAT_1006750c);
    }
    if (*this == '\x03') {
      piVar6 = *(int **)((int)this + 8);
      if (0xf < (uint)piVar6[5]) {
        pvVar1 = (void *)*piVar6;
        pvVar5 = pvVar1;
        if ((0xfff < piVar6[5] + 1U) &&
           (pvVar5 = *(void **)((int)pvVar1 + -4), 0x1f < (uint)((int)pvVar1 + (-4 - (int)pvVar5))))
        goto LAB_100197f1;
        FUN_1002e346(pvVar5);
      }
      piVar6[4] = 0;
      piVar6[5] = 0xf;
      *(undefined1 *)piVar6 = 0;
      FUN_1002e346(*(void **)((int)this + 8));
      *(undefined4 *)((int)this + 8) = 0;
    }
    *(undefined1 *)this = 0;
    break;
  default:
    puVar8 = (uint *)FUN_1000f7b0((undefined1 *)this);
    puVar8 = FUN_10005690(local_a8,puVar8);
    local_14 = 2;
    puVar8 = FUN_10005f20(local_c0,(uint *)"cannot use erase() with ",puVar8);
    local_14 = CONCAT31(local_14._1_3_,3);
    FUN_1000ad90(local_90,0x133,puVar8);
                    /* WARNING: Subroutine does not return */
    __CxxThrowException_8(local_90,&DAT_10067608);
  }
  ExceptionList = local_1c;
  FUN_1002e315(local_24 ^ (uint)&stack0xfffffff0);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10019820 @ 10019820